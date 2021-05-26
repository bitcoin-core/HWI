# -*- mode: python ; coding: utf-8 -*-

import platform
import subprocess

block_cipher = None

def get_libusb_path():
    if platform.system() == 'Windows':
        return 'c:/python3/libusb-1.0.dll'
    if platform.system() == 'Darwin':
        proc = subprocess.Popen(['brew', '--prefix', 'libusb'], stdout=subprocess.PIPE)
        prefix = proc.communicate()[0].rstrip().decode()
        return os.path.join(prefix, "lib", "libusb-1.0.dylib")
    if platform.system() == 'Linux':
        for lib_dir in ['/lib/x86_64-linux-gnu', '/usr/lib64', '/usr/lib', '/lib']:
            libusb_path = os.path.join(lib_dir, 'libusb-1.0.so.0')
            if os.path.exists(libusb_path):
                return libusb_path
    raise RuntimeError(f"Unsupported platform: {platform.system()}")

a = Analysis(['hwi-qt.py'],
             binaries=[(get_libusb_path(), '.')],
             datas=[],
             hiddenimports=[],
             hookspath=['contrib/pyinstaller-hooks/'],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='hwi-qt',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False )
