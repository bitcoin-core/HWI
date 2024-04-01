#! /usr/bin/env python3

import base64
import json
import logging
import sys
import time
from typing import Callable

from . import commands, __version__
from ._cli import HWIArgumentParser
from .errors import handle_errors, DEVICE_NOT_INITIALIZED
from .common import AddressType, Chain

try:
    from .ui.ui_bitbox02pairing import Ui_BitBox02PairingDialog
    from .ui.ui_displayaddressdialog import Ui_DisplayAddressDialog
    from .ui.ui_getxpubdialog import Ui_GetXpubDialog
    from .ui.ui_getkeypooloptionsdialog import Ui_GetKeypoolOptionsDialog
    from .ui.ui_mainwindow import Ui_MainWindow
    from .ui.ui_sendpindialog import Ui_SendPinDialog
    from .ui.ui_setpassphrasedialog import Ui_SetPassphraseDialog
    from .ui.ui_signmessagedialog import Ui_SignMessageDialog
    from .ui.ui_signpsbtdialog import Ui_SignPSBTDialog
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from PySide2.QtGui import QRegExpValidator
from PySide2.QtWidgets import QApplication, QDialog, QDialogButtonBox, QFileDialog, QLineEdit, QMessageBox, QMainWindow, QMenu
from PySide2.QtCore import QCoreApplication, QRegExp, Signal, Slot

def do_command(f, *args, **kwargs):
    result = {}
    with handle_errors(result=result):
        result = f(*args, **kwargs)
    if 'error' in result:
        msg = 'Error: {}\nCode:{}'.format(result['error'], result['code'])
        QMessageBox.critical(None, "An Error Occurred", msg)
        return None
    return result

class SetPassphraseDialog(QDialog):
    def __init__(self):
        super(SetPassphraseDialog, self).__init__()
        self.ui = Ui_SetPassphraseDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set Passphrase')

        self.ui.passphrase_lineedit.setFocus()

class SendPinDialog(QDialog):
    pin_sent_success = Signal()

    def __init__(self, client, prompt_pin=True):
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
        if prompt_pin:
            do_command(commands.prompt_pin, self.client)

    def button_clicked(self, number):
        @Slot()
        def button_clicked_num():
            self.ui.pin_lineedit.setText(self.ui.pin_lineedit.text() + str(number))
        return button_clicked_num

    @Slot()
    def sendpindialog_accepted(self):
        pin = self.ui.pin_lineedit.text()

        # Send the pin
        do_command(commands.send_pin, self.client, pin)
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
        res = do_command(commands.getxpub, self.client, path)
        self.ui.xpub_textedit.setText(res['xpub'])

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

        menu = QMenu()
        self.ui.import_toolbutton.setMenu(menu)
        menu = self.ui.import_toolbutton.menu()
        menu.addAction("From binary").triggered.connect(self.import_binary_clicked)
        menu.addAction("From base64").triggered.connect(self.import_base64_clicked)

        menu = QMenu()
        self.ui.export_toolbutton.setMenu(menu)
        menu = self.ui.export_toolbutton.menu()
        menu.addAction("To binary").triggered.connect(self.export_binary_clicked)
        menu.addAction("To base64").triggered.connect(self.export_base64_clicked)

    @Slot()
    def import_base64_clicked(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file')
        if filename:
            with open(filename, 'r', encoding='utf-8') as f:
                b64 = f.read()
                self.ui.psbt_in_textedit.setPlainText(b64)

    @Slot()
    def import_binary_clicked(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open file', "", "PSBT (*.psbt)")
        if filename:
            with open(filename, 'rb') as f:
                bin = f.read()
                b64 = base64.b64encode(bin).decode()
                self.ui.psbt_in_textedit.setPlainText(b64)

    @Slot()
    def export_base64_clicked(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save file')
        if filename:
            with open(filename, 'w') as f:
                b64 = self.ui.psbt_out_textedit.toPlainText()
                f.write(b64)

    @Slot()
    def export_binary_clicked(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save file', "untitled.psbt")
        if filename:
            with open(filename, 'wb') as f:
                b64 = self.ui.psbt_out_textedit.toPlainText()
                bin = base64.b64decode(b64.encode())
                f.write(bin)

    @Slot()
    def sign_psbt_button_clicked(self):
        psbt_str = self.ui.psbt_in_textedit.toPlainText()
        res = do_command(commands.signtx, self.client, psbt_str)
        self.ui.psbt_out_textedit.setPlainText(res['psbt'])

class SignMessageDialog(QDialog):
    def __init__(self, client):
        super(SignMessageDialog, self).__init__()
        self.ui = Ui_SignMessageDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Sign Message')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.msg_textedit.setFocus()

        self.ui.signmsg_button.clicked.connect(self.signmsg_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def signmsg_button_clicked(self):
        msg_str = self.ui.msg_textedit.toPlainText()
        path = self.ui.path_lineedit.text()
        res = do_command(commands.signmessage, self.client, msg_str, path)
        self.ui.sig_textedit.setPlainText(res['signature'])

class DisplayAddressDialog(QDialog):
    def __init__(self, client):
        super(DisplayAddressDialog, self).__init__()
        self.ui = Ui_DisplayAddressDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Display Address')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.path_lineedit.setFocus()

        self.ui.go_button.clicked.connect(self.go_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def go_button_clicked(self):
        path = self.ui.path_lineedit.text()
        if self.ui.sh_wpkh_radio.isChecked():
            addrtype = AddressType.SH_WIT
        elif self.ui.wpkh_radio.isChecked():
            addrtype = AddressType.WIT
        elif self.ui.pkh_radio.isChecked():
            addrtype = AddressType.LEGACY
        else:
            assert False # How did this happen?
        res = do_command(commands.displayaddress, self.client, path, addr_type=addrtype)
        self.ui.address_lineedit.setText(res['address'])

class GetKeypoolOptionsDialog(QDialog):
    def __init__(self, opts):
        super(GetKeypoolOptionsDialog, self).__init__()
        self.ui = Ui_GetKeypoolOptionsDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set getkeypool options')

        self.ui.start_spinbox.setValue(opts['start'])
        self.ui.end_spinbox.setValue(opts['end'])
        self.ui.internal_checkbox.setChecked(opts['internal'])
        self.ui.keypool_checkbox.setChecked(opts['keypool'])
        self.ui.account_spinbox.setValue(opts['account'])
        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp(r"m(/[0-9]+['Hh]?)+/\*"), None))
        if opts['account_used']:
            self.ui.account_radio.setChecked(True)
            self.ui.path_radio.setChecked(False)
            self.ui.path_lineedit.setEnabled(False)
            self.ui.account_spinbox.setEnabled(True)
            self.ui.account_spinbox.setValue(opts['account'])
        else:
            self.ui.account_radio.setChecked(False)
            self.ui.path_radio.setChecked(True)
            self.ui.path_lineedit.setEnabled(True)
            self.ui.account_spinbox.setEnabled(False)
            self.ui.path_lineedit.setText(opts['path'])
        self.ui.sh_wpkh_radio.setChecked(opts['addrtype'] == AddressType.SH_WIT)
        self.ui.wpkh_radio.setChecked(opts['addrtype'] == AddressType.WIT)
        self.ui.pkh_radio.setChecked(opts['addrtype'] == AddressType.LEGACY)

        self.ui.account_radio.toggled.connect(self.toggle_account)

    @Slot()
    def toggle_account(self, checked):
        if checked:
            self.ui.path_lineedit.setEnabled(False)
            self.ui.account_spinbox.setEnabled(True)
        else:
            self.ui.path_lineedit.setEnabled(True)
            self.ui.account_spinbox.setEnabled(False)

try:
    # Try to import bitbox02 things
    # Not all dependencies may be available, in which case just ignore these two classes
    # The code that needs this should already be (implicitly) guarded by bitbox02_lib imports working
    # so these classes will not be referenced in that case.
    from .devices.bitbox02_lib.util import BitBoxAppNoiseConfig

    class BitBox02PairingDialog(QDialog):
        def __init__(self, pairing_code: str, device_response: Callable[[], bool]):
            super(BitBox02PairingDialog, self).__init__()
            self.ui = Ui_BitBox02PairingDialog()
            self.ui.setupUi(self)
            self.setWindowTitle('Verify BitBox02 pairing code')
            self.ui.pairingCode.setText(pairing_code.replace("\n", "<br>"))
            self.ui.buttonBox.setEnabled(False)
            self.device_response = device_response
            self.painted = False

        def paintEvent(self, ev):
            super().paintEvent(ev)
            self.painted = True

        def enable_buttons(self):
            self.ui.buttonBox.setEnabled(True)

    class BitBox02NoiseConfig(BitBoxAppNoiseConfig):
        """ GUI elements to perform the BitBox02 pairing and attestatoin check """

        def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
            dialog = BitBox02PairingDialog(code, device_response)
            dialog.show()
            # render the window since the next operation is blocking
            while True:
                QCoreApplication.processEvents()
                if dialog.painted:
                    break
                time.sleep(0.1)
            if not device_response():
                return False
            dialog.enable_buttons()
            dialog.exec_()
            return dialog.result() == QDialog.Accepted

        def attestation_check(self, result: bool) -> None:
            if not result:
                QMessageBox.warning(
                    None,
                    "BitBox02 attestation check",
                    "BitBox02 attestation check failed. Your BitBox02 might not be genuine. Please contact support@shiftcrypto.ch if the problem persists.",
                )
except ImportError:
    pass

class HWIQt(QMainWindow):
    def __init__(self, passphrase=None, chain=Chain.MAIN, allow_emulators: bool = False):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle(f'HWI Qt - {chain}')

        self.devices = []
        self.client = None
        self.device_info = {}
        self.passphrase = passphrase
        self.chain = chain
        self.current_dialog = None
        self.getkeypool_opts = {
            'start': 0,
            'end': 1000,
            'account': 0,
            'internal': False,
            'keypool': True,
            'addrtype': AddressType.SH_WIT,
            'path': None,
            'account_used': True
        }
        self.allow_emulators = allow_emulators

        self.ui.enumerate_refresh_button.clicked.connect(self.refresh_clicked)
        self.ui.setpass_button.clicked.connect(self.show_setpassphrasedialog)
        self.ui.sendpin_button.clicked.connect(lambda: self.show_sendpindialog(prompt_pin=True))
        self.ui.getxpub_button.clicked.connect(self.show_getxpubdialog)
        self.ui.signtx_button.clicked.connect(self.show_signpsbtdialog)
        self.ui.signmsg_button.clicked.connect(self.show_signmessagedialog)
        self.ui.display_addr_button.clicked.connect(self.show_displayaddressdialog)
        self.ui.getkeypool_opts_button.clicked.connect(self.show_getkeypooloptionsdialog)
        self.ui.toggle_passphrase_button.clicked.connect(self.toggle_passphrase)

        self.ui.enumerate_combobox.currentIndexChanged.connect(self.get_client_and_device_info)

    def clear_info(self):
        self.ui.getxpub_button.setEnabled(False)
        self.ui.signtx_button.setEnabled(False)
        self.ui.signmsg_button.setEnabled(False)
        self.ui.display_addr_button.setEnabled(False)
        self.ui.getkeypool_opts_button.setEnabled(False)
        self.ui.toggle_passphrase_button.setEnabled(False)
        self.ui.keypool_textedit.clear()
        self.ui.desc_textedit.clear()

    @Slot()
    def refresh_clicked(self):
        if self.client:
            self.client.close()
            self.client = None

        self.devices = commands.enumerate(password=self.passphrase, expert=False, chain=self.chain, allow_emulators=self.allow_emulators)
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
        self.clear_info()

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
            self.clear_info()
            return

        self.ui.getxpub_button.setEnabled(True)
        self.ui.signtx_button.setEnabled(True)
        self.ui.display_addr_button.setEnabled(True)
        self.ui.getkeypool_opts_button.setEnabled(True)

        # Get the client
        self.device_info = self.devices[index - 1]
        self.client = commands.get_client(self.device_info['model'], self.device_info['path'], self.passphrase, self.chain)

        if self.device_info['type'] == 'bitbox02':
            self.client.set_noise_config(BitBox02NoiseConfig())

        self.ui.setpass_button.setEnabled(self.device_info['type'] != 'bitbox02')
        self.ui.signmsg_button.setEnabled(True)
        self.ui.toggle_passphrase_button.setEnabled(self.device_info['type'] in ('trezor', 'keepkey', 'bitbox02', ))

        self.get_device_info()

    def get_device_info(self):
        # Enable the sendpin button if it's a trezor and it needs it
        if self.device_info['needs_pin_sent']:
            self.ui.sendpin_button.setEnabled(True)
            self.clear_info()
            return
        else:
            self.ui.sendpin_button.setEnabled(False)

        # If it isn't initialized, show an error but don't do anything
        if 'code' in self.device_info and self.device_info['code'] == DEVICE_NOT_INITIALIZED:
            self.clear_info()
            QMessageBox.information(None, "Not initialized yet", 'Device is not initialized yet')
            return

        # do getkeypool and getdescriptors
        keypool = do_command(commands.getkeypool, self.client,
                             None if self.getkeypool_opts['account_used'] else self.getkeypool_opts['path'],
                             self.getkeypool_opts['start'],
                             self.getkeypool_opts['end'],
                             self.getkeypool_opts['internal'],
                             self.getkeypool_opts['keypool'],
                             self.getkeypool_opts['account'],
                             self.getkeypool_opts['addrtype'])
        descriptors = do_command(commands.getdescriptors, self.client, self.getkeypool_opts['account'])

        self.ui.keypool_textedit.setPlainText(json.dumps(keypool, indent=2))
        self.ui.desc_textedit.setPlainText(json.dumps(descriptors, indent=2))

    @Slot()
    def show_sendpindialog(self, prompt_pin=True):
        self.current_dialog = SendPinDialog(self.client, prompt_pin)
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

    @Slot()
    def show_signmessagedialog(self):
        self.current_dialog = SignMessageDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_displayaddressdialog(self):
        self.current_dialog = DisplayAddressDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_getkeypooloptionsdialog(self):
        self.current_dialog = GetKeypoolOptionsDialog(self.getkeypool_opts)
        self.current_dialog.accepted.connect(self.getkeypooloptionsdialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def getkeypooloptionsdialog_accepted(self):
        self.getkeypool_opts['start'] = self.current_dialog.ui.start_spinbox.value()
        self.getkeypool_opts['end'] = self.current_dialog.ui.end_spinbox.value()
        self.getkeypool_opts['internal'] = self.current_dialog.ui.internal_checkbox.isChecked()
        self.getkeypool_opts['keypool'] = self.current_dialog.ui.keypool_checkbox.isChecked()
        self.getkeypool_opts['addrtype'] = AddressType.LEGACY
        if self.current_dialog.ui.sh_wpkh_radio.isChecked():
            self.getkeypool_opts['addrtype'] = AddressType.SH_WIT
        if self.current_dialog.ui.wpkh_radio.isChecked():
            self.getkeypool_opts['addrtype'] = AddressType.WIT
        if self.current_dialog.ui.pkh_radio.isChecked():
            self.getkeypool_opts['addrtype'] = AddressType.LEGACY
        if self.current_dialog.ui.account_radio.isChecked():
            self.getkeypool_opts['account'] = self.current_dialog.ui.account_spinbox.value()
            self.getkeypool_opts['account_used'] = True
        else:
            self.getkeypool_opts['path'] = self.current_dialog.ui.path_lineedit.text()
            self.getkeypool_opts['account_used'] = False
        self.current_dialog = None
        self.get_device_info()

    @Slot()
    def toggle_passphrase(self):
        do_command(commands.toggle_passphrase, self.client)
        if self.device_info['model'] == "keepkey":
            self.show_sendpindialog(prompt_pin=False)

def process_gui_commands(cli_args):
    parser = HWIArgumentParser(description='Hardware Wallet Interface Qt, version {}.\nInteractively access and send commands to a hardware wallet device with a GUI. Responses are in JSON format.'.format(__version__))
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)', default=None)
    parser.add_argument('--chain', help='Select chain to work with', type=Chain.argparse, choices=list(Chain), default=Chain.MAIN)
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument("--emulators", help="Enable enumeration and detection of device emulators", action="store_true", dest="allow_emulators")

    # Parse arguments again for anything entered over stdin
    args = parser.parse_args(cli_args)

    result = {}

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # Qt setup
    app = QApplication()

    window = HWIQt(args.password, args.chain, args.allow_emulators)

    window.refresh_clicked()

    window.show()
    ret = app.exec_()
    result = {'success': ret == 0}

    return result

def main():
    result = process_gui_commands(sys.argv[1:])
    print(json.dumps(result))
