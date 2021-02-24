#! /usr/bin/env python3

import unittest
import filecmp
from os import makedirs, remove, removedirs, walk, path
from hwilib._cli import process_commands

class TestUdevRulesInstaller(unittest.TestCase):
    INSTALLATION_FOLDER = 'rules.d'
    SOURCE_FOLDER = '../hwilib/udev'

    @classmethod
    def setUpClass(cls):
        # Create directory where copy the udev rules to.
        makedirs(cls.INSTALLATION_FOLDER, exist_ok=True)

    @classmethod
    def tearDownClass(self):
        for root, _, files in walk(self.INSTALLATION_FOLDER, topdown=False):
            for name in files:
                remove(path.join(root, name))
        removedirs(self.INSTALLATION_FOLDER)

    def test_rules_file_are_copied(self):
        process_commands(['installudevrules', '--location', self.INSTALLATION_FOLDER])
        # Assert files wre copied
        for _, _, files in walk(self.INSTALLATION_FOLDER, topdown=False):
            for file_name in files:
                src = path.join(self.SOURCE_FOLDER, file_name)
                tgt = path.join(self.INSTALLATION_FOLDER, file_name)
                self.assertTrue(filecmp.cmp(src, tgt))

if __name__ == "__main__":
    unittest.main()
