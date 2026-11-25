# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['aiohttp', 'cryptography', 'cryptography.hazmat.primitives.asymmetric.ec', 'cryptography.hazmat.primitives.ciphers.aead', 'skyhuiyu.capture.launcher']
hiddenimports += collect_submodules('qrcode')


a = Analysis(
    ['entry.py'],
    pathex=['.'],
    binaries=[],
    datas=[('skyhuiyu/web', 'skyhuiyu/web')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['mitmproxy', 'tkinter', 'numpy', 'cv2'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='skyhuiyu',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
