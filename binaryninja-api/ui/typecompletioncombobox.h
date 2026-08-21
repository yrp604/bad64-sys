#pragma once

#include <QtCore/QStringListModel>
#ifndef BINARYNINJAUI_BINDINGS
	#include <QtCore/QThread>
#endif
#include <optional>
#include "completioncombobox.h"
#include "binaryninjaapi.h"
#include "uitypes.h"


#ifdef BINARYNINJAUI_BINDINGS
// QThread has issues working in the bindings on some platforms
class GetTypesListThread;
#else

/*!

	\ingroup typedialog
*/
class BINARYNINJAUIAPI GetTypesListThread : public QThread
{
	Q_OBJECT

	QStringList m_allTypes;
	std::function<void()> m_completeFunc;
	std::mutex m_mutex;
	bool m_done;
	BinaryNinja::TypeContainer m_typeContainer;

protected:
	virtual void run() override;

public:
	GetTypesListThread(BinaryNinja::TypeContainer typeContainer, const std::function<void()>& completeFunc);
	void cancel();

	const QStringList& getTypes() const { return m_allTypes; }
};
#endif

//! A CompletionComboBox pre-configured for type name autocompletion.
//!
//! Fetches type names from a TypeContainer in a background thread and populates
//! the completer model. Respects the ui.types.substring and
//! ui.types.maxAutoFeaturesCount settings.
//!
//! Optionally manages a persistent input history stored in QSettings.
class BINARYNINJAUIAPI TypeCompletionComboBox : public CompletionComboBox
{
	Q_OBJECT

	QStringListModel* m_model;
	GetTypesListThread* m_updateThread = nullptr;
	QStringList m_historyEntries;
	int m_historySize;

	void customEvent(QEvent* event) override;

public:
	TypeCompletionComboBox(std::optional<BinaryNinja::TypeContainer> typeContainer, QWidget* parent = nullptr,
		QString existing = QString());
	~TypeCompletionComboBox();

	//! Commit the current text to the persistent input history.
	void commitHistory();

	QStringListModel* completionModel() const { return m_model; }
};
