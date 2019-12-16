#! /usr/bin/env python3

from . import commands

try:
    from .ui.ui_mainwindow import Ui_MainWindow
    from .ui.ui_setpassphrasedialog import Ui_SetPassphraseDialog
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from PySide2.QtWidgets import QApplication, QDialog, QMainWindow
from PySide2.QtCore import Slot

class SetPassphraseDialog(QDialog):
    def __init__(self):
        super(SetPassphraseDialog, self).__init__()
        self.ui = Ui_SetPassphraseDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set Passphrase')

        self.ui.passphrase_lineedit.setFocus()

class HWIQt(QMainWindow):
    def __init__(self):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('HWI Qt')

        self.devices = []
        self.client = None
        self.passphrase = ''
        self.current_dialog = None

        self.ui.enumerate_refresh_button.clicked.connect(self.refresh_clicked)
        self.ui.setpass_button.clicked.connect(self.show_setpassphrasedialog)

    @Slot()
    def refresh_clicked(self):
        self.devices = commands.enumerate(self.passphrase)
        self.ui.enumerate_combobox.clear()
        self.ui.enumerate_combobox.addItem('')
        for dev in self.devices:
            fingerprint = 'none'
            if 'fingerprint' in dev:
                fingerprint = dev['fingerprint']
            dev_str = '{} fingerprint:{} path:{}'.format(dev['model'], fingerprint, dev['path'])
            self.ui.enumerate_combobox.addItem(dev_str)

    @Slot()
    def show_setpassphrasedialog(self):
        self.current_dialog = SetPassphraseDialog()
        self.current_dialog.accepted.connect(self.setpassphrasedialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def setpassphrasedialog_accepted(self):
        self.passphrase = self.current_dialog.ui.passphrase_lineedit.text()
        self.current_dialog = None

def main():
    app = QApplication()

    window = HWIQt()

    window.refresh_clicked()

    window.show()
    app.exec_()
