#pragma once

#include "uitypes.h"
#include <QtGui/QKeyEvent>
#include <QtWidgets/QComboBox>

//! CompletionComboBox is a subclass of QComboBox intended to have a more
//! familiar user experience when working with auto-completion.
//!
//! Most notably, the <TAB> keypress is intercepted so that the tab key can be
//! used to cycle through completion options. This is similar the behavior found
//! in most text editors and IDEs.
//!
//! Additionally, the combo box is editable and uses case-sensitive matching,
//! popup-style completion, and a "no insert" policy by default.
class BINARYNINJAUIAPI CompletionComboBox : public QComboBox {
    Q_OBJECT

	bool m_forwardReturnEvents = true;

    //! Manually cycle the selected completion suggestion, forward by default.
    bool cycleCompletion(bool forward = true);

protected:
    bool event(QEvent* event) override;

public:
    CompletionComboBox(QWidget* parent = nullptr);

	void setForwardReturnEvents(bool forward) { m_forwardReturnEvents = forward; }

Q_SIGNALS:
    void enterPressed();
};
