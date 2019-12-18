#! /usr/bin/env python3

import json

from . import commands

try:
    from .ui.ui_getxpubdialog import Ui_GetXpubDialog
    from .ui.ui_mainwindow import Ui_MainWindow
    from .ui.ui_sendpindialog import Ui_SendPinDialog
    from .ui.ui_setpassphrasedialog import Ui_SetPassphraseDialog
    from .ui.ui_signpsbtdialog import Ui_SignPSBTDialog
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from PySide2.QtGui import QRegExpValidator
from PySide2.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLineEdit, QMainWindow
from PySide2.QtCore import QRegExp, Signal, Slot

class SetPassphraseDialog(QDialog):
    def __init__(self):
        super(SetPassphraseDialog, self).__init__()
        self.ui = Ui_SetPassphraseDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set Passphrase')

        self.ui.passphrase_lineedit.setFocus()

class SendPinDialog(QDialog):
    pin_sent_success = Signal()

    def __init__(self, client):
        super(SendPinDialog, self).__init__()
        self.ui = Ui_SendPinDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Send Pin')
        self.client = client
        self.ui.pin_lineedit.setFocus()
        self.ui.pin_lineedit.setValidator(QRegExpValidator(QRegExp("[1-9]+"), None))
        self.ui.pin_lineedit.setEchoMode(QLineEdit.Password)

        self.ui.p1_button.clicked.connect(self.button_clicked(1))
        self.ui.p2_button.clicked.connect(self.button_clicked(2))
        self.ui.p3_button.clicked.connect(self.button_clicked(3))
        self.ui.p4_button.clicked.connect(self.button_clicked(4))
        self.ui.p5_button.clicked.connect(self.button_clicked(5))
        self.ui.p6_button.clicked.connect(self.button_clicked(6))
        self.ui.p7_button.clicked.connect(self.button_clicked(7))
        self.ui.p8_button.clicked.connect(self.button_clicked(8))
        self.ui.p9_button.clicked.connect(self.button_clicked(9))

        self.accepted.connect(self.sendpindialog_accepted)
        commands.prompt_pin(self.client)

    def button_clicked(self, number):
        @Slot()
        def button_clicked_num():
            self.ui.pin_lineedit.setText(self.ui.pin_lineedit.text() + str(number))
        return button_clicked_num

    @Slot()
    def sendpindialog_accepted(self):
        pin = self.ui.pin_lineedit.text()

        # Send the pin
        commands.send_pin(self.client, pin)
        self.client.close()
        self.client = None
        self.pin_sent_success.emit()

class GetXpubDialog(QDialog):
    def __init__(self, client):
        super(GetXpubDialog, self).__init__()
        self.ui = Ui_GetXpubDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Get xpub')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.path_lineedit.setFocus()
        self.ui.buttonBox.button(QDialogButtonBox.Close).setAutoDefault(False)

        self.ui.getxpub_button.clicked.connect(self.getxpub_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def getxpub_button_clicked(self):
        path = self.ui.path_lineedit.text()
        res = commands.getxpub(self.client, path)
        self.ui.xpub_lineedit.setText(res['xpub'])

class SignPSBTDialog(QDialog):
    def __init__(self, client):
        super(SignPSBTDialog, self).__init__()
        self.ui = Ui_SignPSBTDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Sign PSBT')
        self.client = client

        self.ui.psbt_in_textedit.setFocus()

        self.ui.sign_psbt_button.clicked.connect(self.sign_psbt_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def sign_psbt_button_clicked(self):
        psbt_str = self.ui.psbt_in_textedit.toPlainText()
        res = commands.signtx(self.client, psbt_str)
        self.ui.psbt_out_textedit.setPlainText(res['psbt'])

class HWIQt(QMainWindow):
    def __init__(self):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('HWI Qt')

        self.devices = []
        self.client = None
        self.device_info = {}
        self.passphrase = ''
        self.current_dialog = None

        self.ui.enumerate_refresh_button.clicked.connect(self.refresh_clicked)
        self.ui.setpass_button.clicked.connect(self.show_setpassphrasedialog)
        self.ui.sendpin_button.clicked.connect(self.show_sendpindialog)
        self.ui.getxpub_button.clicked.connect(self.show_getxpubdialog)
        self.ui.signtx_button.clicked.connect(self.show_signpsbtdialog)

        self.ui.enumerate_combobox.currentIndexChanged.connect(self.get_client_and_device_info)

    @Slot()
    def refresh_clicked(self):
        if self.client:
            self.client.close()
            self.client = None

        self.devices = commands.enumerate(self.passphrase)
        self.ui.enumerate_combobox.currentIndexChanged.disconnect()
        self.ui.enumerate_combobox.clear()
        self.ui.enumerate_combobox.addItem('')
        for dev in self.devices:
            fingerprint = 'none'
            if 'fingerprint' in dev:
                fingerprint = dev['fingerprint']
            dev_str = '{} fingerprint:{} path:{}'.format(dev['model'], fingerprint, dev['path'])
            self.ui.enumerate_combobox.addItem(dev_str)
        self.ui.enumerate_combobox.currentIndexChanged.connect(self.get_client_and_device_info)

    @Slot()
    def show_setpassphrasedialog(self):
        self.current_dialog = SetPassphraseDialog()
        self.current_dialog.accepted.connect(self.setpassphrasedialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def setpassphrasedialog_accepted(self):
        self.passphrase = self.current_dialog.ui.passphrase_lineedit.text()
        self.current_dialog = None

    @Slot()
    def get_client_and_device_info(self, index):
        self.ui.sendpin_button.setEnabled(False)
        if index == 0:
            return

        # Get the client
        self.device_info = self.devices[index - 1]
        self.client = commands.get_client(self.device_info['model'], self.device_info['path'], self.passphrase)
        self.get_device_info()

    def get_device_info(self):
        # Enable the sendpin button if it's a trezor and it needs it
        if self.device_info['needs_pin_sent']:
            self.ui.sendpin_button.setEnabled(True)
            return
        else:
            self.ui.sendpin_button.setEnabled(False)

        # do getkeypool and getdescriptors
        keypool = commands.getkeypool(self.client, 'm/49h/0h/0h/*', 0, 1000, False, True, 0, False, True)
        descriptors = commands.getdescriptors(self.client, 0)

        self.ui.keypool_textedit.setPlainText(json.dumps(keypool, indent=2))
        self.ui.desc_textedit.setPlainText(json.dumps(descriptors, indent=2))

    @Slot()
    def show_sendpindialog(self):
        self.current_dialog = SendPinDialog(self.client)
        self.current_dialog.pin_sent_success.connect(self.sendpindialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def sendpindialog_accepted(self):
        self.current_dialog = None

        curr_index = self.ui.enumerate_combobox.currentIndex()
        self.refresh_clicked()
        self.ui.enumerate_combobox.setCurrentIndex(curr_index)

    @Slot()
    def show_getxpubdialog(self):
        self.current_dialog = GetXpubDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_signpsbtdialog(self):
        self.current_dialog = SignPSBTDialog(self.client)
        self.current_dialog.exec_()

def main():
    app = QApplication()

    window = HWIQt()

    window.refresh_clicked()

    window.show()
    app.exec_()
