@echo off
setlocal enabledelayedexpansion

:: Change to the directory where this script is located
:: (Running as Admin defaults to C:\Windows\System32)
cd /d "%~dp0"

:: Set UTF-8 encoding for console
chcp 65001 >nul 2>&1

echo ============================================
echo   AAG Technical Audit Tool - Windows Setup
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

:: Check for nmap
echo [*] Checking nmap...
set NMAP_FOUND=0
where nmap >nul 2>&1
if %errorLevel% equ 0 (
    set NMAP_FOUND=1
    goto :nmap_found
)
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    set NMAP_FOUND=1
    goto :nmap_found
)
if exist "C:\Program Files\Nmap\nmap.exe" (
    set NMAP_FOUND=1
    goto :nmap_found
)

:: nmap not found - try to install
echo [!] nmap not found. Attempting to install...
powershell -Command "Get-Command winget -ErrorAction SilentlyContinue" >nul 2>&1
if %errorLevel% equ 0 (
    echo [*] Installing nmap via winget...
    powershell -Command "winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements"
    if %errorLevel% equ 0 (
        echo [+] nmap installed successfully!
        set NMAP_FOUND=1
    ) else (
        echo [!] Failed to install nmap via winget.
        echo     Please install manually from https://nmap.org/download.html
    )
) else (
    echo [!] winget not available. Please install nmap manually from:
    echo     https://nmap.org/download.html
)

:nmap_found
if %NMAP_FOUND% equ 1 (
    echo [+] nmap ready.
)
echo.

:: Check for Ollama
echo [*] Checking Ollama...
set OLLAMA_FOUND=0
where ollama >nul 2>&1
if %errorLevel% equ 0 (
    set OLLAMA_FOUND=1
    goto :ollama_found
)
if exist "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" (
    set OLLAMA_FOUND=1
    goto :ollama_found
)
if exist "C:\Program Files\Ollama\ollama.exe" (
    set OLLAMA_FOUND=1
    goto :ollama_found
)

:: Ollama not found - try to install
echo [!] Ollama not found. Attempting to install...
echo [*] Downloading Ollama installer...
powershell -Command "Invoke-WebRequest -Uri 'https://ollama.com/download/OllamaSetup.exe' -OutFile '%TEMP%\OllamaSetup.exe'"
if %errorLevel% equ 0 (
    echo [*] Running Ollama installer...
    start /wait "" "%TEMP%\OllamaSetup.exe" /SILENT
    del "%TEMP%\OllamaSetup.exe" >nul 2>&1
    echo [+] Ollama installed!
    set OLLAMA_FOUND=1
    :: Wait for Ollama service to start
    timeout /t 3 /nobreak >nul
) else (
    echo [!] Failed to download Ollama. Please install manually from:
    echo     https://ollama.com/download
)

:ollama_found
if %OLLAMA_FOUND% equ 1 (
    echo [+] Ollama ready.
    :: Check if model is available, pull if not
    echo [*] Checking for qwen2.5:7b model...
    ollama list 2>nul | findstr /C:"qwen2.5:7b" >nul
    if %errorLevel% neq 0 (
        echo [*] Pulling qwen2.5:7b model (this may take a few minutes)...
        ollama pull qwen2.5:7b
        if %errorLevel% equ 0 (
            echo [+] Model downloaded successfully!
        ) else (
            echo [!] Failed to pull model. The app will try again when needed.
        )
    ) else (
        echo [+] Model qwen2.5:7b ready.
    )
)
echo.

:: Check for PowerShell 7 (required for Zero Trust and Azure Inventory tabs)
echo [*] Checking PowerShell 7...
set PWSH_FOUND=0
where pwsh >nul 2>&1
if %errorLevel% equ 0 (
    set PWSH_FOUND=1
    goto :pwsh_found
)
if exist "C:\Program Files\PowerShell\7\pwsh.exe" (
    set PWSH_FOUND=1
    goto :pwsh_found
)

:: PowerShell 7 not found - try to install
echo [!] PowerShell 7 not found. Required for Zero Trust and Azure Inventory.
powershell -Command "Get-Command winget -ErrorAction SilentlyContinue" >nul 2>&1
if %errorLevel% equ 0 (
    echo [*] Installing PowerShell 7 via winget...
    powershell -Command "winget install --id Microsoft.PowerShell -e --accept-source-agreements --accept-package-agreements"
    if %errorLevel% equ 0 (
        echo [+] PowerShell 7 installed successfully!
        set PWSH_FOUND=1
    ) else (
        echo [!] Failed to install PowerShell 7.
        echo     Zero Trust and Azure Inventory tabs will not work.
        echo     Install manually: https://aka.ms/powershell-release?tag=stable
    )
) else (
    echo [!] winget not available. PowerShell 7 not installed.
    echo     Zero Trust and Azure Inventory tabs will not work.
    echo     Install manually: https://aka.ms/powershell-release?tag=stable
)

:pwsh_found
if %PWSH_FOUND% equ 1 (
    echo [+] PowerShell 7 ready.
)
echo.

:: Run the app
echo ============================================
echo   All dependencies ready - Starting app...
echo ============================================
echo.
%PYTHON% "%~dp0app.py"

pause
