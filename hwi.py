#! /usr/bin/env python3

# Hardware wallet interaction script

from hwilib.commands import process_commands

import sys
import json

if __name__ == '__main__':
    result = process_commands(sys.argv[1:])
    print(json.dumps(result))
