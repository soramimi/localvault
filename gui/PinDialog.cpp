#include "PinDialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QMessageBox>

PinDialog::PinDialog(Mode mode, QWidget *parent)
    : QDialog(parent)
    , mode_(mode)
{
    setWindowTitle(mode == Mode::Setup ? tr("Set Vault PIN") : tr("Unlock Vault"));

    QFormLayout *formLayout = new QFormLayout(this);

    pinEdit_ = new QLineEdit(this);
    pinEdit_->setEchoMode(QLineEdit::Password);
    pinEdit_->setMaxLength(64);
    formLayout->addRow(mode == Mode::Setup ? tr("New PIN:") : tr("PIN:"), pinEdit_);

    if (mode == Mode::Setup) {
        confirmEdit_ = new QLineEdit(this);
        confirmEdit_->setEchoMode(QLineEdit::Password);
        confirmEdit_->setMaxLength(64);
        formLayout->addRow(tr("Confirm PIN:"), confirmEdit_);
    }

    QDialogButtonBox *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        Qt::Horizontal,
        this);
    connect(buttons, &QDialogButtonBox::accepted, this, &PinDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &PinDialog::reject);
    formLayout->addRow(buttons);

    setLayout(formLayout);
}

SecureBuffer PinDialog::pin() const
{
    SecureBuffer result;
    QString text = pinEdit_->text();
    QByteArray utf8 = text.toUtf8();
    result.assign(utf8.constData(), utf8.size());
    result.lock();
    return result;
}

void PinDialog::accept()
{
    if (mode_ == Mode::Setup && confirmEdit_) {
        if (pinEdit_->text() != confirmEdit_->text()) {
            QMessageBox::warning(this, tr("PIN Mismatch"), tr("The two PINs do not match."));
            return;
        }
        if (pinEdit_->text().isEmpty()) {
            QMessageBox::warning(this, tr("Invalid PIN"), tr("PIN cannot be empty."));
            return;
        }
    }

    QDialog::accept();
}

SecureBuffer PinDialog::requestPin(QWidget *parent, bool *ok)
{
    PinDialog dialog(Mode::Unlock, parent);
    bool accepted = (dialog.exec() == QDialog::Accepted);
    if (ok) {
        *ok = accepted;
    }
    if (accepted) {
        return dialog.pin();
    }
    return SecureBuffer();
}

SecureBuffer PinDialog::setupPin(QWidget *parent, bool *ok)
{
    PinDialog dialog(Mode::Setup, parent);
    bool accepted = (dialog.exec() == QDialog::Accepted);
    if (ok) {
        *ok = accepted;
    }
    if (accepted) {
        return dialog.pin();
    }
    return SecureBuffer();
}
