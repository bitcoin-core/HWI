#! /usr/bin/env python3

from . import commands

try:
    from .ui.ui_mainwindow import Ui_MainWindow
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from PySide2.QtWidgets import QApplication, QMainWindow
from PySide2.QtCore import Slot

class HWIQt(QMainWindow):
    def __init__(self):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('HWI Qt')

        self.devices = []

        self.ui.enumerate_refresh_button.clicked.connect(self.refresh_clicked)

    @Slot()
    def refresh_clicked(self):
        self.devices = commands.enumerate()
        self.ui.enumerate_combobox.clear()
        for dev in self.devices:
            fingerprint = 'none'
            if 'fingerprint' in dev:
                fingerprint = dev['fingerprint']
            dev_str = '{} fingerprint:{} path:{}'.format(dev['model'], fingerprint, dev['path'])
            self.ui.enumerate_combobox.addItem(dev_str)

def main():
    app = QApplication()

    window = HWIQt()

    window.refresh_clicked()

    window.show()
    app.exec_()
