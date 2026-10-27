# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：把 FlowRunner 打成可执行文件（带终端窗口，
双击运行后在浏览器打开 http://127.0.0.1:8765 使用）。

本地构建：pip install pyinstaller && pyinstaller FlowRunner.spec
产物在 dist/FlowRunner/（FlowRunner 可执行文件 + 依赖文件，打包成 zip 再发）。
GitHub Actions 会自动做这件事，见 .github/workflows/build.yml。

注意：
- 用 onedir（文件夹）而不是 onefile：启动快，不用每次解压上百 MB。
- 保留终端窗口（console=True）：程序要停在终端里运行，关掉即停止服务。
- index.html 已通过 app.py 的 sys._MEIPASS 定位，打包后能找到。
- 程序仍需本机装 Google Chrome（Playwright 用 channel="chrome"，
  不打包浏览器），且首次使用要设账号池主密码。
"""
from PyInstaller.utils.hooks import collect_all

datas = [("index.html", ".")]
binaries = []
hiddenimports = [
    "uvicorn.lifespan.on",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.loops.auto",
    "multipart",
    "cryptography",
]
# Playwright 的驱动文件必须一起打进去，否则打包后运行时找不到驱动。
_tmp = collect_all("playwright")
datas += _tmp[0]
binaries += _tmp[1]
hiddenimports += _tmp[2]

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FlowRunner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="FlowRunner",
)
