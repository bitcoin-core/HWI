#! /usr/bin/env python3

# Firmware downloader script

if __name__ == '__main__':
    from hwilib.firmware import main
    main()
else:
    raise ImportError('firmwaredl is not importable')
