@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python launcher 'py' was not found.
    echo Run install_libraries.bat after installing Python 3.10+.
    pause
    exit /b 1
)

py -m ctfbot.gui
if errorlevel 1 (
    echo.
    echo [ERROR] GUI failed to start.
    echo Try running install_libraries.bat first.
    pause
    exit /b 1
)
