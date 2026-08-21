#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtCore/QStringListModel>
#include <QtWidgets/QComboBox>
#include <QtCore/QTimer>
#include "binaryninjaapi.h"
#include "uitypes.h"
#include "typecompletioncombobox.h"


#ifdef BINARYNINJAUI_BINDINGS
// QThread has issues working in the bindings on some platforms
class ParseTypeThread;
#else

/*!

	\defgroup typedialog TypeDialog
 	\ingroup uiapi
*/

Q_DECLARE_METATYPE(BinaryNinja::QualifiedNameAndType);

/*! QThread subclass for handling type string parsing to avoid UI interruptions.

    \ingroup typedialog
*/
class ParseTypeThread : public QThread
{
	Q_OBJECT

	std::optional<BinaryNinja::TypeContainer> m_typeContainer;
	std::string m_text;

	void run() override;

  Q_SIGNALS:
	void parsingComplete(bool valid, BinaryNinja::QualifiedNameAndType type, QString error);

  public:
	ParseTypeThread(std::optional<BinaryNinja::TypeContainer> typeContainer, QString text);
	void cancel();
};
#endif

/*!

    \ingroup typedialog
*/
class BINARYNINJAUIAPI TypeDialog : public QDialog
{
	Q_OBJECT

	TypeCompletionComboBox* m_combo;
	QStringListModel* m_model;
	QLabel* m_prompt;
	QString m_promptText;
	std::optional<BinaryNinja::TypeContainer> m_typeContainer;
	bool m_resultValid = true;
	bool m_resolved = false;
	BinaryNinja::QualifiedNameAndType m_type;
	QPushButton* m_acceptButton;
	QTimer* m_updateTimer;
	QTimer* m_parseTimer;
	bool m_isParsing = false;
	QPalette m_defaultPalette;
	QString m_parseError;

	void commitHistory();
	void saveLocation();
	void reject();
	void accept();
	void linkActivated(const QString& link);

  private Q_SLOTS:
	void accepted();
	void checkParse();
	void typeParsed(bool valid, BinaryNinja::QualifiedNameAndType type, QString error);
	void updateTimerEvent();

  public:
	TypeDialog(QWidget* parent, std::optional<BinaryNinja::TypeContainer> typeContainer, const QString& title = "Specify Type",
	    const QString& prompt = "Enter Type Name", const QString& existing = "");
	~TypeDialog();
	BinaryNinja::QualifiedNameAndType getType() const { return m_type; }
};
