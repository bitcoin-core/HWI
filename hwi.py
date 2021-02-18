#! /usr/bin/env python3

# Hardware wallet interaction script

if __name__ == '__main__':
    from hwilib._cli import main
    main()
else:
    raise ImportError('hwi is not importable. Import hwilib instead')
