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


string TransformContext::GetTransformName() const
{
	char* name = BNTransformContextGetTransformName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


string TransformContext::GetFileName() const
{
	char* name = BNTransformContextGetFileName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


Ref<BinaryView> TransformContext::GetInput() const
{
	return new BinaryView(BNTransformContextGetInput(m_object));
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
	return new TransformContext(BNNewTransformContextReference(parent));
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
	return new TransformContext(BNNewTransformContextReference(child));
}


Ref<TransformContext> TransformContext::CreateChild(const DataBuffer& data, const string& filename)
{
	BNTransformContext* child = BNTransformContextCreateChild(m_object, data.GetBufferObject(), filename.c_str());
	if (!child)
		return nullptr;
	return new TransformContext(BNNewTransformContextReference(child));
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
