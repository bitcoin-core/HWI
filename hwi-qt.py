#! /usr/bin/env python3

if __name__ == '__main__':
    from hwilib.gui import main
    main()
else:
    raise ImportError('hwi-qt is not importable. Import hwilib instead')
