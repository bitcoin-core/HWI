# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import os
import sys

from mnemonic import Mnemonic

from . import device
from .exceptions import Cancelled
from .messages import PinMatrixRequestType, WordRequestType

PIN_MATRIX_DESCRIPTION = """
Use the numeric keypad to describe number positions. The layout is:
    7 8 9
    4 5 6
    1 2 3
""".strip()

RECOVERY_MATRIX_DESCRIPTION = """
Use the numeric keypad to describe positions.
For the word list use only left and right keys.
Use backspace to correct an entry.

The keypad layout is:
    7 8 9     7 | 9
    4 5 6     4 | 6
    1 2 3     1 | 3
""".strip()

PIN_GENERIC = None
PIN_CURRENT = PinMatrixRequestType.Current
PIN_NEW = PinMatrixRequestType.NewFirst
PIN_CONFIRM = PinMatrixRequestType.NewSecond


def echo(msg):
    print(msg, file=sys.stderr)

def prompt(msg, hide_input=False):
    if hide_input:
        import getpass
        return getpass.getpass(msg + ' :\n')
    else:
        return input(msg + ':\n')

class PassphraseUI:
    def __init__(self, passphrase):
        self.passphrase = passphrase
        self.pinmatrix_shown = False
        self.prompt_shown = False
        self.always_prompt = False
        self.return_passphrase = True

    def button_request(self, code):
        if not self.prompt_shown:
            echo("Please confirm action on your Trezor device")
        if not self.always_prompt:
            self.prompt_shown = True

    def get_pin(self, code=None):
        raise NotImplementedError('get_pin is not needed')

    def disallow_passphrase(self):
        self.return_passphrase = False

    def get_passphrase(self):
        if self.return_passphrase:
            return self.passphrase
        raise ValueError('Passphrase from Host is not allowed for Trezor T')

def mnemonic_words(expand=False, language="english"):
    if expand:
        wordlist = Mnemonic(language).wordlist
    else:
        wordlist = set()

    def expand_word(word):
        if not expand:
            return word
        if word in wordlist:
            return word
        matches = [w for w in wordlist if w.startswith(word)]
        if len(matches) == 1:
            return word
        echo("Choose one of: " + ", ".join(matches))
        raise KeyError(word)

    def get_word(type):
        assert type == WordRequestType.Plain
        while True:
            try:
                word = prompt("Enter one word of mnemonic")
                return expand_word(word)
            except KeyError:
                pass

    return get_word
