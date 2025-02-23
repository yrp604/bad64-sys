#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


ScriptingOutputListener::ScriptingOutputListener()
{
	m_callbacks.context = this;
	m_callbacks.output = OutputCallback;
	m_callbacks.warning = WarningCallback;
	m_callbacks.error = ErrorCallback;
	m_callbacks.inputReadyStateChanged = InputReadyStateChangedCallback;
}


void ScriptingOutputListener::OutputCallback(void* ctxt, const char* text)
{
	ScriptingOutputListener* listener = (ScriptingOutputListener*)ctxt;
	listener->NotifyOutput(text);
}


void ScriptingOutputListener::WarningCallback(void* ctxt, const char* text)
{
	ScriptingOutputListener* listener = (ScriptingOutputListener*)ctxt;
	listener->NotifyWarning(text);
}


void ScriptingOutputListener::ErrorCallback(void* ctxt, const char* text)
{
	ScriptingOutputListener* listener = (ScriptingOutputListener*)ctxt;
	listener->NotifyError(text);
}


void ScriptingOutputListener::InputReadyStateChangedCallback(void* ctxt, BNScriptingProviderInputReadyState state)
{
	ScriptingOutputListener* listener = (ScriptingOutputListener*)ctxt;
	listener->NotifyInputReadyStateChanged(state);
}


void ScriptingOutputListener::NotifyOutput(const string&) {}


void ScriptingOutputListener::NotifyWarning(const string&) {}


void ScriptingOutputListener::NotifyError(const string&) {}


void ScriptingOutputListener::NotifyInputReadyStateChanged(BNScriptingProviderInputReadyState) {}


ScriptingInstance::ScriptingInstance(ScriptingProvider* provider)
{
	BNScriptingInstanceCallbacks cb;
	cb.context = this;
	cb.destroyInstance = DestroyInstanceCallback;
	cb.externalRefTaken = nullptr;
	cb.externalRefReleased = nullptr;
	cb.executeScriptInput = ExecuteScriptInputCallback;
	cb.cancelScriptInput = CancelScriptInputCallback;
	cb.releaseBinaryView = ReleaseBinaryViewCallback;
	cb.setCurrentBinaryView = SetCurrentBinaryViewCallback;
	cb.setCurrentFunction = SetCurrentFunctionCallback;
	cb.setCurrentBasicBlock = SetCurrentBasicBlockCallback;
	cb.setCurrentAddress = SetCurrentAddressCallback;
	cb.setCurrentSelection = SetCurrentSelectionCallback;
	cb.completeInput = CompleteInputCallback;
	cb.stop = StopCallback;
	AddRefForRegistration();
	m_object = BNInitScriptingInstance(provider->GetObject(), &cb);
}


ScriptingInstance::ScriptingInstance(BNScriptingInstance* instance)
{
	m_object = instance;
}


void ScriptingInstance::DestroyInstanceCallback(void* ctxt)
{
	ScriptingInstance* instance = (ScriptingInstance*)ctxt;
	instance->DestroyInstance();
}


BNScriptingProviderExecuteResult ScriptingInstance::ExecuteScriptInputCallback(void* ctxt, const char* input)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	return instance->ExecuteScriptInput(input);
}


void ScriptingInstance::CancelScriptInputCallback(void* ctxt)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	instance->CancelScriptInput();
}


void ScriptingInstance::ReleaseBinaryViewCallback(void* ctxt, BNBinaryView* view)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	Ref<BinaryView> object = view ? new BinaryView(BNNewViewReference(view)) : nullptr;
	instance->ReleaseBinaryView(object);
}


void ScriptingInstance::SetCurrentBinaryViewCallback(void* ctxt, BNBinaryView* view)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	Ref<BinaryView> object = view ? new BinaryView(BNNewViewReference(view)) : nullptr;
	instance->SetCurrentBinaryView(object);
}


void ScriptingInstance::SetCurrentFunctionCallback(void* ctxt, BNFunction* func)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	Ref<Function> object = func ? new Function(BNNewFunctionReference(func)) : nullptr;
	instance->SetCurrentFunction(object);
}


void ScriptingInstance::SetCurrentBasicBlockCallback(void* ctxt, BNBasicBlock* block)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	Ref<BasicBlock> object = block ? new BasicBlock(BNNewBasicBlockReference(block)) : nullptr;
	instance->SetCurrentBasicBlock(object);
}


void ScriptingInstance::SetCurrentAddressCallback(void* ctxt, uint64_t addr)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	instance->SetCurrentAddress(addr);
}


void ScriptingInstance::SetCurrentSelectionCallback(void* ctxt, uint64_t begin, uint64_t end)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	instance->SetCurrentSelection(begin, end);
}


char* ScriptingInstance::CompleteInputCallback(void* ctxt, const char* text, uint64_t state)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	std::string completed = instance->CompleteInput(text, state);
	if (completed.c_str() == nullptr)
	{
		LogWarn("ScriptingInstance::CompleteInput returned nullptr; replacing with empty string.");
		completed = "";
	}
	return BNAllocString(completed.c_str());
}


void ScriptingInstance::StopCallback(void* ctxt)
{
	CallbackRef<ScriptingInstance> instance(ctxt);
	instance->Stop();
}


void ScriptingInstance::DestroyInstance()
{
	ReleaseForRegistration();
}


void ScriptingInstance::CancelScriptInput() {}


void ScriptingInstance::ReleaseBinaryView(BinaryView*) {}


void ScriptingInstance::SetCurrentBinaryView(BinaryView*) {}


void ScriptingInstance::SetCurrentFunction(Function*) {}


void ScriptingInstance::SetCurrentBasicBlock(BasicBlock*) {}


void ScriptingInstance::SetCurrentAddress(uint64_t) {}


void ScriptingInstance::SetCurrentSelection(uint64_t, uint64_t) {}


std::string ScriptingInstance::CompleteInput(const std::string&, uint64_t)
{
	return "";
}


void ScriptingInstance::Output(const string& text)
{
	BNNotifyOutputForScriptingInstance(m_object, text.c_str());
}


void ScriptingInstance::Warning(const string& text)
{
	BNNotifyWarningForScriptingInstance(m_object, text.c_str());
}


void ScriptingInstance::Error(const string& text)
{
	BNNotifyErrorForScriptingInstance(m_object, text.c_str());
}


void ScriptingInstance::InputReadyStateChanged(BNScriptingProviderInputReadyState state)
{
	BNNotifyInputReadyStateForScriptingInstance(m_object, state);
}


BNScriptingProviderInputReadyState ScriptingInstance::GetInputReadyState()
{
	return BNGetScriptingInstanceInputReadyState(m_object);
}


void ScriptingInstance::RegisterOutputListener(ScriptingOutputListener* listener)
{
	BNRegisterScriptingInstanceOutputListener(m_object, &listener->GetCallbacks());
}


void ScriptingInstance::UnregisterOutputListener(ScriptingOutputListener* listener)
{
	BNUnregisterScriptingInstanceOutputListener(m_object, &listener->GetCallbacks());
}


std::string ScriptingInstance::GetDelimiters()
{
	return BNGetScriptingInstanceDelimiters(m_object);
}


void ScriptingInstance::SetDelimiters(const std::string& delimiters)
{
	BNSetScriptingInstanceDelimiters(m_object, delimiters.c_str());
}


void ScriptingInstance::Stop() {}


CoreScriptingInstance::CoreScriptingInstance(BNScriptingInstance* instance) : ScriptingInstance(instance) {}


BNScriptingProviderExecuteResult CoreScriptingInstance::ExecuteScriptInput(const string& input)
{
	return BNExecuteScriptInput(m_object, input.c_str());
}

BNScriptingProviderExecuteResult CoreScriptingInstance::ExecuteScriptInputFromFilename(const string& filename)
{
	return BNExecuteScriptInputFromFilename(m_object, filename.c_str());
}

void CoreScriptingInstance::CancelScriptInput()
{
	BNCancelScriptInput(m_object);
}


void CoreScriptingInstance::ReleaseBinaryView(BinaryView* view)
{
	BNScriptingInstanceReleaseBinaryView(m_object, view ? view->GetObject() : nullptr);
}


void CoreScriptingInstance::SetCurrentBinaryView(BinaryView* view)
{
	BNSetScriptingInstanceCurrentBinaryView(m_object, view ? view->GetObject() : nullptr);
}


void CoreScriptingInstance::SetCurrentFunction(Function* func)
{
	BNSetScriptingInstanceCurrentFunction(m_object, func ? func->GetObject() : nullptr);
}


void CoreScriptingInstance::SetCurrentBasicBlock(BasicBlock* block)
{
	BNSetScriptingInstanceCurrentBasicBlock(m_object, block ? block->GetObject() : nullptr);
}


void CoreScriptingInstance::SetCurrentAddress(uint64_t addr)
{
	BNSetScriptingInstanceCurrentAddress(m_object, addr);
}


void CoreScriptingInstance::SetCurrentSelection(uint64_t begin, uint64_t end)
{
	BNSetScriptingInstanceCurrentSelection(m_object, begin, end);
}


std::string CoreScriptingInstance::CompleteInput(const std::string& text, uint64_t state)
{
	char* result = BNScriptingInstanceCompleteInput(m_object, text.c_str(), state);
	std::string ret = result;
	BNFreeString(result);
	return ret;
}


void CoreScriptingInstance::Stop()
{
	BNStopScriptingInstance(m_object);
}


ScriptingProvider::ScriptingProvider(const string& name, const string& apiName) :
    m_nameForRegister(name), m_apiNameForRegister(apiName)
{}


ScriptingProvider::ScriptingProvider(BNScriptingProvider* provider)
{
	m_object = provider;
}


BNScriptingInstance* ScriptingProvider::CreateInstanceCallback(void* ctxt)
{
	ScriptingProvider* provider = (ScriptingProvider*)ctxt;
	Ref<ScriptingInstance> instance = provider->CreateNewInstance();
	return instance ? BNNewScriptingInstanceReference(instance->GetObject()) : nullptr;
}


bool ScriptingProvider::LoadModuleCallback(void* ctxt, const char* repository, const char* module, bool force)
{
	ScriptingProvider* provider = (ScriptingProvider*)ctxt;
	return BNLoadScriptingProviderModule(provider->GetObject(), repository, module, force);
}


bool ScriptingProvider::InstallModulesCallback(void* ctxt, const char* modules)
{
	ScriptingProvider* provider = (ScriptingProvider*)ctxt;
	return BNInstallScriptingProviderModules(provider->GetObject(), modules);
}


string ScriptingProvider::GetName()
{
	char* providerNameRaw = BNGetScriptingProviderName(m_object);
	string providerName(providerNameRaw);
	BNFreeString(providerNameRaw);
	return providerName;
}


string ScriptingProvider::GetAPIName()
{
	char* providerNameRaw = BNGetScriptingProviderAPIName(m_object);
	string providerName(providerNameRaw);
	BNFreeString(providerNameRaw);
	return providerName;
}


vector<Ref<ScriptingProvider>> ScriptingProvider::GetList()
{
	size_t count;
	BNScriptingProvider** list = BNGetScriptingProviderList(&count);
	vector<Ref<ScriptingProvider>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreScriptingProvider(list[i]));
	BNFreeScriptingProviderList(list);
	return result;
}


Ref<ScriptingProvider> ScriptingProvider::GetByName(const string& name)
{
	BNScriptingProvider* result = BNGetScriptingProviderByName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreScriptingProvider(result);
}


Ref<ScriptingProvider> ScriptingProvider::GetByAPIName(const string& name)
{
	BNScriptingProvider* result = BNGetScriptingProviderByAPIName(name.c_str());
	if (!result)
		return nullptr;
	return new CoreScriptingProvider(result);
}


void ScriptingProvider::Register(ScriptingProvider* provider)
{
	BNScriptingProviderCallbacks cb;
	cb.context = provider;
	cb.createInstance = CreateInstanceCallback;
	cb.loadModule = LoadModuleCallback;
	cb.installModules = InstallModulesCallback;
	provider->m_object =
	    BNRegisterScriptingProvider(provider->m_nameForRegister.c_str(), provider->m_apiNameForRegister.c_str(), &cb);
}


CoreScriptingProvider::CoreScriptingProvider(BNScriptingProvider* provider) : ScriptingProvider(provider) {}


Ref<ScriptingInstance> CoreScriptingProvider::CreateNewInstance()
{
	BNScriptingInstance* result = BNCreateScriptingProviderInstance(m_object);
	if (!result)
		return nullptr;
	return new CoreScriptingInstance(result);
}


bool CoreScriptingProvider::LoadModule(const std::string& repository, const std::string& module, bool force)
{
	return BNLoadScriptingProviderModule(m_object, repository.c_str(), module.c_str(), force);
}


bool CoreScriptingProvider::InstallModules(const std::string& modules)
{
	return BNInstallScriptingProviderModules(m_object, modules.c_str());
}
