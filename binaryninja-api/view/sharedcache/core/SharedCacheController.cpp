#include "SharedCacheController.h"
#include "MachOProcessor.h"
#include "ObjC.h"

using namespace BinaryNinja;
using namespace BinaryNinja::DSC;

// Unique ID for a given Binary View.
typedef uint64_t ViewId;

std::shared_mutex GlobalControllersMutex;

std::map<ViewId, DSCRef<SharedCacheController>>& GlobalControllers()
{
	// To make initialization order consistent we place the static in a function.
	static std::map<ViewId, DSCRef<SharedCacheController>> g_controllers = {};
	return g_controllers;
}

ViewId GetViewIdFromFileMetadata(const FileMetadata& file)
{
	// Currently the view id is just the views session id.
	// NOTE: If we want more than one shared cache controller per view we would need to make this more unique.
	return file.GetSessionId();
}

void DeleteController(const FileMetadata& file)
{
	const auto id = GetViewIdFromFileMetadata(file);
	std::unique_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto& controllers = GlobalControllers();
	if (auto it = controllers.find(id); it != controllers.end())
	{
		auto controller = it->second;
		// Someone is still holding the controller, lets warn about this.
		// 2 is expected here because we have one held in `controllers` and one held by `controller`.
		if (controller->m_refs > 2)
			LogWarnF("Deleting SharedCacheController for view {:#x}, but there are still {} references", id,
				controller->m_refs.load());

		// Go through the file accessor cache and remove the entries we reference.
		auto& fileAccessorCache = FileAccessorCache::Global();
		for (const auto& entry : controller->GetCache().GetEntries())
		{
			auto accessorId = GetCacheAccessorID(entry.GetFilePath());
			fileAccessorCache.RemoveAccessor(accessorId);
		}

		controllers.erase(it);
		LogDebugF("Deleted SharedCacheController for view {:?}", file.GetFilename().c_str());
	}
}

void RegisterSharedCacheControllerDestructor()
{
	BNObjectDestructionCallbacks callbacks = {};
	callbacks.destructFileMetadata = [](void* ctx, BNFileMetadata* obj) -> void {
		const auto file = FileMetadata(obj);
		DeleteController(file);
	};
	BNRegisterObjectDestructionCallbacks(&callbacks);
}

SharedCacheController::SharedCacheController(SharedCache&& cache, Ref<Logger> logger) : m_cache(std::move(cache))
{
	INIT_DSC_API_OBJECT();
	m_logger = std::move(logger);
	m_loadedRegions = {};
	m_loadedImages = {};
	m_processObjC = true;
	m_processCFStrings = true;
	m_regionFilter = std::regex(".*LINKEDIT.*");
}

DSCRef<SharedCacheController> SharedCacheController::Initialize(BinaryView& view, SharedCache&& cache)
{
	auto id = GetViewIdFromFileMetadata(*view.GetFile());
	std::unique_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto logger = new Logger("SharedCache.Controller", view.GetFile()->GetSessionId());
	DSCRef<SharedCacheController> controller = new SharedCacheController(std::move(cache), logger);

	// Pull the settings from the view.
	if (Ref<Settings> settings = view.GetLoadSettings(VIEW_NAME))
	{
		if (settings->Contains("loader.dsc.processObjC"))
			controller->m_processObjC = settings->Get<bool>("loader.dsc.processObjC", &view);
		if (settings->Contains("loader.dsc.processCFStrings"))
			controller->m_processCFStrings = settings->Get<bool>("loader.dsc.processCFStrings", &view);
		if (settings->Contains("loader.dsc.regionFilter"))
			controller->m_regionFilter = std::regex(settings->Get<std::string>("loader.dsc.regionFilter", &view));
	}

	// TODO: Support old shared cache metadata
	// TODO: Not strictly necessary as the user has already loaded the information into the database, this would just
	// TODO: prevent incidental extra work from being done when loading a region or image.
	// const uint64_t oldStateCount = view.GetUIntMetadata(OLD_METADATA_KEY_COUNT);

	// Check the view auto metadata for shared cache information.
	// This effectively restores the state of the opened database to when it was last saved.
	// NOTE: We store on the parent view because hilariously, the metadata is not present until after view init.
	if (const auto metadata = view.GetParentView()->QueryMetadata(METADATA_KEY))
		controller->LoadMetadata(*metadata);

	GlobalControllers().insert({id, controller});
	return controller;
}

DSCRef<SharedCacheController> SharedCacheController::FromView(const BinaryView& view)
{
	auto id = GetViewIdFromFileMetadata(*view.GetFile());
	std::shared_lock<std::shared_mutex> lock(GlobalControllersMutex);
	auto& dscViews = GlobalControllers();
	auto dscView = dscViews.find(id);
	if (dscView == dscViews.end())
		return nullptr;
	return dscView->second;
}

bool SharedCacheController::ApplyRegionAtAddress(BinaryView& view, const uint64_t address)
{
	auto region = m_cache.GetRegionAt(address);
	if (!region)
		return false;
	return ApplyRegion(view, *region);
}

bool SharedCacheController::ApplyRegion(BinaryView& view, const CacheRegion& region)
{
	std::unique_lock<std::shared_mutex> lock(m_loadMutex);
	// Loads the given region into the BinaryView and marks it as loaded.
	// First check to make sure we haven't already loaded the region.
	if (m_loadedRegions.find(region.start) != m_loadedRegions.end())
		return false;

	// Skip filtered regions, this defaults to just LINKEDIT regions.
	if (std::regex_match(region.name, m_regionFilter))
	{
		m_logger->LogDebugF("Skipping filtered region at {:#x}", region.start);
		return false;
	}

	auto vm = m_cache.GetVirtualMemory();
	DataBuffer buffer = {};
	try
	{
		buffer = vm->ReadBuffer(region.start, region.size);
	}
	catch (std::exception& e)
	{
		// This happens if we have not mapped in all the relevant entries.
		m_logger->LogErrorF("Failed to read region: {}", e.what());
		return false;
	}

	// Unique memory region name so that we don't cause collisions.
	// TODO: Better name? I dont really think so...
	const auto memoryRegionName = fmt::format("{}_0x{:x}", region.name, region.start);

	// NOTE: Adding a data memory region will store the entire contents of the region in the BNDB.
	// TODO: We can use the AddRemoteMemoryRegion if we want to reload on view init.
	// TODO: ^ The above is only useful if we assume that all files will be available across database loads.
	// TODO: we might allow a user to select non-persisted memory regions as an option.
	bool addedMemoryRegion = view.GetMemoryMap()->AddDataMemoryRegion(memoryRegionName, region.start, buffer, region.flags);
	if (!addedMemoryRegion)
		return false;

	// TODO: We might want to make this auto if we decide to "reload" all loaded region in view init.
	// If we are not associated with an image we can create a section here to set the semantics.
	// This is important for stub regions, as they will deref non image data that we want to retrieve the value of.
	if (region.type != CacheRegionType::Image)
	{
		// Adding a user section will mark all functions for updates unless we disable this.
		// Because images are known separate compilation units, we have a real reason to make sure we don't mark all previously
		// analyzed functions as updated.
		auto prevDisabledState = view.GetFunctionAnalysisUpdateDisabled();
		view.SetFunctionAnalysisUpdateDisabled(true);
		view.AddUserSection(memoryRegionName, region.start, region.size, region.SectionSemanticsForRegion());
		view.SetFunctionAnalysisUpdateDisabled(prevDisabledState);
	}

	m_loadedRegions.insert(region.start);

	// TODO: This needs to be done in a "database save" callback.
	view.StoreMetadata(METADATA_KEY, GetMetadata());

	return true;
}

bool SharedCacheController::IsRegionLoaded(const CacheRegion& region)
{
	std::shared_lock<std::shared_mutex> lock(m_loadMutex);
	return std::any_of(m_loadedRegions.begin(), m_loadedRegions.end(), [&](const auto& loadedRegion) {
		return loadedRegion == region.start;
	});
}

bool SharedCacheController::ApplyImage(BinaryView& view, const CacheImage& image)
{
	// Load all regions of an image and mark the image as loaded.
	// NOTE: The regions lock m_loadMutex themselves, so we do not hold it up here.
	view.BeginBulkAddSegments();
	bool loadedRegion = false;
	for (const auto& regionStart : image.regionStarts)
		if (ApplyRegionAtAddress(view, regionStart))
			loadedRegion = true;
	view.EndBulkAddSegments();

	// The ApplyRegionAtAddress no longer holds the lock, we can take it now.
	std::unique_lock<std::shared_mutex> lock(m_loadMutex);
	// If there was no loaded regions than we just want to forgo loading the image.
	// We also skip if we already loaded the image itself. We do this after loading regions
	// as we regions have their own check.
	if (!loadedRegion || m_loadedImages.find(image.headerAddress) != m_loadedImages.end())
		return false;

	if (image.header)
	{
		// Header information is applied to the view here, such as sections.
		auto machoProcessor = SharedCacheMachOProcessor(&view, m_cache.GetVirtualMemory());

		// Adding a user section will mark all functions for updates unless we disable this.
		// Because images are known separate compilation units, we have a real reason to make sure we don't mark all previously
		// analyzed functions as updated.
		auto prevDisabledState = view.GetFunctionAnalysisUpdateDisabled();
		view.SetFunctionAnalysisUpdateDisabled(true);
		machoProcessor.ApplyHeader(GetCache(), *image.header);
		view.SetFunctionAnalysisUpdateDisabled(prevDisabledState);

		// Load objective-c information.
		auto objcProcessor = DSCObjC::SharedCacheObjCProcessor(&view, image.headerAddress);
		try
		{
			if (m_processObjC)
				objcProcessor.ProcessObjCData();
			if (m_processCFStrings)
				objcProcessor.ProcessObjCLiterals();
		}
		catch (std::exception& e)
		{
			// Let the user know there was an error in processing the objc stuff but let the image load
			// regardless, as its non-critical.
			m_logger->LogErrorF("Failed to process ObjC information: {}", e.what());
		}
	}

	m_loadedImages.insert(image.headerAddress);

	m_logger->LogInfoF("Loaded image: '{}'", image.path);

	// TODO: This needs to be done in a "database save" callback.
	// NOTE: We store on the parent view because hilariously, the view metadata is not available in view init.
	view.GetParentView()->StoreMetadata(METADATA_KEY, GetMetadata());

	// TODO: Partial failure state (i.e. 2 regions loaded, one failed)
	return true;
}

bool SharedCacheController::IsImageLoaded(const CacheImage& image)
{
	std::shared_lock<std::shared_mutex> lock(m_loadMutex);
	return std::any_of(m_loadedImages.begin(), m_loadedImages.end(), [&](const auto& loadedImage) {
		return loadedImage == image.headerAddress;
	});
}

Ref<Metadata> SharedCacheController::GetMetadata() const
{
	std::map<std::string, Ref<Metadata>> controllerMeta;

	std::vector<uint64_t> loadedImages;
	std::vector<uint64_t> loadedRegions;
	loadedImages.reserve(m_loadedImages.size());
	loadedRegions.reserve(m_loadedRegions.size());
	for (const auto& loadedImage : m_loadedImages)
		loadedImages.push_back(loadedImage);
	for (const auto& loadedRegion : m_loadedRegions)
		loadedRegions.push_back(loadedRegion);

	controllerMeta["loadedImages"] = new Metadata(loadedImages);
	controllerMeta["loadedRegions"] = new Metadata(loadedRegions);

	return new Metadata(controllerMeta);
}

void SharedCacheController::LoadMetadata(const Metadata& metadata)
{
	auto controllerMeta = metadata.GetKeyValueStore();
	if (controllerMeta.find("loadedImages") != controllerMeta.end())
	{
		const auto loadedImages = controllerMeta["loadedImages"]->GetUnsignedIntegerList();
		for (const auto& image : loadedImages)
			m_loadedImages.insert(image);
	}

	if (controllerMeta.find("loadedRegions") != controllerMeta.end())
	{
		const auto loadedRegions = controllerMeta["loadedRegions"]->GetUnsignedIntegerList();
		for (const auto& region : loadedRegions)
			m_loadedImages.insert(region);
	}
}
