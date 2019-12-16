#! /usr/bin/env python3

from . import commands

try:
    from .ui.ui_mainwindow import Ui_MainWindow
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from PySide2.QtWidgets import QApplication, QMainWindow

class HWIQt(QMainWindow):
    def __init__(self):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('HWI Qt')

def main():
    devices = commands.enumerate()
    print(devices)

    app = QApplication()

    window = HWIQt()
    window.show()

    app.exec_()
