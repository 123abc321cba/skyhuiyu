@echo off
setlocal
title SkyHuiyu 会话抓取
cd /d "%~dp0"

rem ============================================================
rem  抓取栈要写 hosts、改系统代理，必须管理员。
rem  net session 在非管理员下返回非 0，用它判断比拼 whoami 稳定。
rem ============================================================
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo.
    echo   需要管理员权限，正在弹 UAC ...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

if not exist "skyhuiyu.exe" (
    echo.
    echo   [X] 没找到 skyhuiyu.exe
    echo       这个 bat 必须和 exe 放在同一个目录里。
    echo.
    pause
    exit /b 1
)

echo ============================================================
echo    SkyHuiyu   会话抓取
echo ============================================================
echo.
echo    这个窗口要一直开着 —— 它在替游戏提供代理。
echo.
echo    1^) 启动光遇启动器，扫码登录，进到主界面
echo    2^) 看到「会话已抓取！」就说明好了
echo    3^) 按 Ctrl+C 退出，会自动还原系统代理与 hosts
echo.
echo    抓不到就多登一次；缺 level/通行密钥的话进一次地图再抓。
echo.
echo ------------------------------------------------------------
echo.

skyhuiyu.exe --capture enable
set RC=%errorlevel%

echo.
if not "%RC%"=="0" (
    echo 退出码 %RC% —— 抓取栈没起来，看上面的错误信息。
) else (
    echo 已退出。
)
echo.
pause
exit /b %RC%
