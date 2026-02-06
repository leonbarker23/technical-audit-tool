@echo off
setlocal enabledelayedexpansion

:: Change to the directory where this script is located
:: (Running as Admin defaults to C:\Windows\System32)
cd /d "%~dp0"

:: Set UTF-8 encoding for console
chcp 65001 >nul 2>&1

echo ============================================
echo   Technical Audit Analysis - Windows Setup
echo ============================================
echo.
echo [*] Output folder: %cd%
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] This tool requires Administrator privileges.
    echo     Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Check for Python
set PYTHON=
where python >nul 2>&1
if %errorLevel% equ 0 (
    set PYTHON=python
    goto :python_found
)
where python3 >nul 2>&1
if %errorLevel% equ 0 (
    set PYTHON=python3
    goto :python_found
)
where py >nul 2>&1
if %errorLevel% equ 0 (
    set PYTHON=py
    goto :python_found
)

:: Python not found - try to install
echo [!] Python not found. Attempting to install...
echo.

:: Try winget first (via PowerShell for reliability)
powershell -Command "Get-Command winget -ErrorAction SilentlyContinue" >nul 2>&1
if %errorLevel% equ 0 (
    echo [*] Installing Python via winget...
    powershell -Command "winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements"
    if %errorLevel% equ 0 (
        echo.
        echo [+] Python installed successfully!
        echo [!] IMPORTANT: Close this window and run this script again.
        echo     ^(PATH changes require a new terminal session^)
        echo.
        pause
        exit /b 0
    )
)

:: Winget failed or unavailable - download installer directly
echo [*] Downloading Python installer...
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\python_installer.exe'"
if %errorLevel% equ 0 (
    echo [*] Running Python installer...
    echo     IMPORTANT: Check "Add Python to PATH" at the bottom of the installer!
    start /wait "" "%TEMP%\python_installer.exe"
    del "%TEMP%\python_installer.exe" >nul 2>&1
    echo.
    echo [+] Python installation complete.
    echo [!] Close this window and run this script again.
    echo.
    pause
    exit /b 0
)

echo [!] Failed to install Python automatically.
echo     Please install manually from https://www.python.org/downloads/
echo     IMPORTANT: Check "Add Python to PATH" during installation!
pause
exit /b 1

:python_found
echo [+] Python found: %PYTHON%

:: Check for pip packages
echo [*] Checking Python packages...
%PYTHON% -c "import flask" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Installing Flask...
    %PYTHON% -m pip install flask --quiet
)

%PYTHON% -c "import ollama" >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Installing ollama Python package...
    %PYTHON% -m pip install ollama --quiet
)

echo [+] Python packages ready.
echo.

:: Run the app
echo [*] Starting Discovery Tool...
%PYTHON% "%~dp0app.py"

pause
