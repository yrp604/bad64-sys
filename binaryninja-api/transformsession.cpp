#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


TransformSession::TransformSession(const string& filename)
{
	m_object = BNCreateTransformSession(filename.c_str());
}


TransformSession::TransformSession(const string& filename, BNTransformSessionMode mode)
{
	m_object = BNCreateTransformSessionWithMode(filename.c_str(), mode);
}


TransformSession::TransformSession(Ref<BinaryView> initialView)
{
	m_object = BNCreateTransformSessionFromBinaryView(initialView->GetObject());
}


TransformSession::TransformSession(Ref<BinaryView> initialView, BNTransformSessionMode mode)
{
	m_object = BNCreateTransformSessionFromBinaryViewWithMode(initialView->GetObject(), mode);
}


TransformSession::TransformSession(BNTransformSession* session)
{
	m_object = session;
}


TransformSession::~TransformSession()
{
}


Ref<BinaryView> TransformSession::GetCurrentView() const
{
	return new BinaryView(BNTransformSessionGetCurrentView(m_object));
}


Ref<TransformContext> TransformSession::GetRootContext() const
{
	return new TransformContext(BNTransformSessionGetRootContext(m_object));
}


Ref<TransformContext> TransformSession::GetCurrentContext() const
{
	return new TransformContext(BNTransformSessionGetCurrentContext(m_object));
}


bool TransformSession::Process()
{
	return BNTransformSessionProcess(m_object);
}


bool TransformSession::HasAnyStages() const
{
	return BNTransformSessionHasAnyStages(m_object);
}


bool TransformSession::HasSinglePath() const
{
	return BNTransformSessionHasSinglePath(m_object);
}


vector<Ref<TransformContext>> TransformSession::GetSelectedContexts() const
{
	size_t count;
	BNTransformContext** contexts = BNTransformSessionGetSelectedContexts(m_object, &count);
	vector<Ref<TransformContext>> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(new TransformContext(BNNewTransformContextReference(contexts[i])));

	BNFreeTransformContextList(contexts, count);
	return result;
}


void TransformSession::SetSelectedContexts(const vector<Ref<TransformContext>>& contexts)
{
	BNTransformContext** cContexts = new BNTransformContext*[contexts.size()];
	for (size_t i = 0; i < contexts.size(); i++)
		cContexts[i] = contexts[i]->GetObject();

	BNTransformSessionSetSelectedContexts(m_object, cContexts, contexts.size());
	delete[] cContexts;
}


bool TransformSession::RequiresUserInput() const
{
	return BNTransformSessionRequiresUserInput(m_object);
}


bool TransformSession::HasMultipleFileChoices() const
{
	return BNTransformSessionHasMultipleFileChoices(m_object);
}


vector<string> TransformSession::GetAvailableFileChoices() const
{
	size_t count;
	char** files = BNTransformSessionGetAvailableFileChoices(m_object, &count);

	vector<string> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
	{
		result.push_back(files[i]);
	}

	BNFreeStringList(files, count);
	return result;
}


bool TransformSession::SelectFiles(const vector<string>& selectedFiles)
{
	const char** cFiles = new const char*[selectedFiles.size()];
	for (size_t i = 0; i < selectedFiles.size(); i++)
	{
		cFiles[i] = selectedFiles[i].c_str();
	}

	bool result = BNTransformSessionSelectFiles(m_object, cFiles, selectedFiles.size());
	delete[] cFiles;
	return result;
}


bool TransformSession::ProcessWithUserInput()
{
	return BNTransformSessionProcessWithUserInput(m_object);
}
