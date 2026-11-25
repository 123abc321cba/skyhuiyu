@echo off
rem 打包成单文件 exe：dist\skyhuiyu.exe
rem 产物不依赖目标机装 Python；首次运行会在 %APPDATA%\SkyHuiyu 建库。
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1

python -m PyInstaller ^
  --noconfirm --clean --onefile ^
  --name skyhuiyu ^
  --paths . ^
  --add-data "skyhuiyu\web;skyhuiyu\web" ^
  --collect-submodules qrcode ^
  --hidden-import aiohttp ^
  --hidden-import cryptography ^
  --hidden-import cryptography.hazmat.primitives.asymmetric.ec ^
  --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
  --exclude-module mitmproxy ^
  --exclude-module tkinter ^
  --exclude-module numpy ^
  --exclude-module cv2 ^
  entry.py

if errorlevel 1 (
  echo 打包失败
  pause
  exit /b 1
)
echo.
echo 产物: %cd%\dist\skyhuiyu.exe
echo 自检: dist\skyhuiyu.exe --check
endlocal
