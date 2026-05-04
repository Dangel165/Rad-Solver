@echo off
setlocal
cd /d "%~dp0"

echo [CTF Bot] Checking Python launcher...
where py >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python launcher 'py' was not found.
    echo Install Python 3.10+ from https://www.python.org/downloads/ and enable "Add python.exe to PATH".
    pause
    exit /b 1
)

echo [CTF Bot] Upgrading pip...
py -m pip install --upgrade pip
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip.
    pause
    exit /b 1
)

echo [CTF Bot] Installing libraries from requirements.txt...
py -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo [OK] Libraries are ready.
echo You can now run: run_gui.bat
pause
