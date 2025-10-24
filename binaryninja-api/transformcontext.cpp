#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


TransformContext::TransformContext(BNTransformContext* context)
{
	m_object = context;
}


TransformContext::~TransformContext()
{
}


Ref<BinaryView> TransformContext::GetInput() const
{
	return new BinaryView(BNTransformContextGetInput(m_object));
}


string TransformContext::GetFileName() const
{
	char* name = BNTransformContextGetFileName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string TransformContext::GetTransformName() const
{
	char* name = BNTransformContextGetTransformName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


void TransformContext::SetTransformParameters(const map<string, DataBuffer>& params)
{
	BNTransformParameter* list = new BNTransformParameter[params.size()];
	size_t idx = 0;
	for (const auto& param : params)
	{
		list[idx].name = param.first.c_str();
		list[idx].value = param.second.GetBufferObject();
		idx++;
	}

	BNTransformContextSetTransformParameters(m_object, list, params.size());
	delete[] list;
}


void TransformContext::SetTransformParameter(const string& name, const DataBuffer& data)
{
	BNTransformContextSetTransformParameter(m_object, name.c_str(), data.GetBufferObject());
}


bool TransformContext::HasTransformParameter(const string& name) const
{
	return BNTransformContextHasTransformParameter(m_object, name.c_str());
}


void TransformContext::ClearTransformParameter(const string& name)
{
	BNTransformContextClearTransformParameter(m_object, name.c_str());
}


string TransformContext::GetExtractionMessage() const
{
	char* message = BNTransformContextGetExtractionMessage(m_object);
	string result = message;
	BNFreeString(message);
	return result;
}


BNTransformResult TransformContext::GetExtractionResult() const
{
	return BNTransformContextGetExtractionResult(m_object);
}


BNTransformResult TransformContext::GetTransformResult() const
{
	return BNTransformContextGetTransformResult(m_object);
}


Ref<Metadata> TransformContext::GetMetadata() const
{
	return new Metadata(BNTransformContextGetMetadata(m_object));
}


Ref<TransformContext> TransformContext::GetParent() const
{
	BNTransformContext* parent = BNTransformContextGetParent(m_object);
	if (!parent)
		return nullptr;
	return new TransformContext(parent);
}


size_t TransformContext::GetChildCount() const
{
	return BNTransformContextGetChildCount(m_object);
}


vector<Ref<TransformContext>> TransformContext::GetChildren() const
{
	size_t count;
	BNTransformContext** contexts = BNTransformContextGetChildren(m_object, &count);

	vector<Ref<TransformContext>> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
		result.push_back(new TransformContext(BNNewTransformContextReference(contexts[i])));

	BNFreeTransformContextList(contexts, count);
	return result;
}


Ref<TransformContext> TransformContext::GetChild(const string& filename) const
{
	BNTransformContext* child = BNTransformContextGetChild(m_object, filename.c_str());
	if (!child)
		return nullptr;
	return new TransformContext(child);
}


Ref<TransformContext> TransformContext::SetChild(const DataBuffer& data, const string& filename, BNTransformResult result, const std::string& message)
{
	BNTransformContext* child = BNTransformContextSetChild(m_object, data.GetBufferObject(), filename.c_str(), result, message.c_str());
	if (!child)
		return nullptr;
	return new TransformContext(child);
}


bool TransformContext::IsLeaf() const
{
	return BNTransformContextIsLeaf(m_object);
}


bool TransformContext::IsRoot() const
{
	return BNTransformContextIsRoot(m_object);
}


vector<string> TransformContext::GetAvailableFiles() const
{
	size_t count;
	char** files = BNTransformContextGetAvailableFiles(m_object, &count);

	vector<string> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
	{
		result.push_back(files[i]);
	}

	BNFreeStringList(files, count);
	return result;
}


void TransformContext::SetAvailableFiles(const vector<string>& files)
{
	const char** cFiles = new const char*[files.size()];
	for (size_t i = 0; i < files.size(); i++)
	{
		cFiles[i] = files[i].c_str();
	}

	BNTransformContextSetAvailableFiles(m_object, cFiles, files.size());
	delete[] cFiles;
}


bool TransformContext::HasAvailableFiles() const
{
	return BNTransformContextHasAvailableFiles(m_object);
}


vector<string> TransformContext::GetRequestedFiles() const
{
	size_t count;
	char** files = BNTransformContextGetRequestedFiles(m_object, &count);

	vector<string> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
	{
		result.push_back(files[i]);
	}

	BNFreeStringList(files, count);
	return result;
}


void TransformContext::SetRequestedFiles(const vector<string>& files)
{
	const char** cFiles = new const char*[files.size()];
	for (size_t i = 0; i < files.size(); i++)
	{
		cFiles[i] = files[i].c_str();
	}

	BNTransformContextSetRequestedFiles(m_object, cFiles, files.size());
	delete[] cFiles;
}


bool TransformContext::HasRequestedFiles() const
{
	return BNTransformContextHasRequestedFiles(m_object);
}


bool TransformContext::IsDatabase() const
{
	return BNTransformContextIsDatabase(m_object);
}
