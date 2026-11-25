@echo off
rem SkyHuiyu 电脑端启动器
rem 这个 bat 只做三件事：确认 exe 在、别开第二个实例、把 exe 拉起来。
rem 历史坑：以前是 `start "" skyhuiyu.exe`，exe 起不来的时候错误
rem 信息跟着那个新控制台一起消失，用户只看到一句
rem 「应用程序无法正常启动(0xc0000142)」—— 看不到是谁拦的、缺什么。
rem 现在改成最小化启动 + 失败时 pause，报错留在窗口里能截图。
cd /d "%~dp0"

if not exist "skyhuiyu.exe" (
    echo.
    echo   [X] 没找到 skyhuiyu.exe
    echo       这个 bat 必须和 exe 放在同一个目录里。
    echo.
    pause
    exit /b 1
)

rem 已经在跑就别开第二个。第二个实例会抢 8765 端口，
rem 起来就退出，看起来跟"启动不了"一模一样。
netstat -ano | findstr /C:":8765 " | findstr /C:"LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo   面板已经在运行，直接开浏览器。
    start "" "http://127.0.0.1:8765/"
    timeout /t 2 >nul
    exit /b 0
)

rem /min：不挡视线；出错时 pause 把窗口留住，报错看得见。
start "" /min cmd /c "cd /d ""%~dp0"" && skyhuiyu.exe || pause"
exit /b 0
