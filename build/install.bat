@echo off
setlocal
set "SOURCE_EXE=%~dp0Blowfish.exe"
set "INSTALL_DIR=%ProgramFiles%\Blowfish"
set "INSTALL_EXE=%INSTALL_DIR%\Blowfish.exe"

net session >nul 2>&1
if errorlevel 1 (
    if /i "%~1"=="__elevated" (
        echo ERROR: Administrative privileges are required.
        exit /b 1
    )

    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '__elevated' -Verb RunAs"
    if errorlevel 1 (
        echo ERROR: Elevation was cancelled or failed.
        exit /b 1
    )
    exit /b 0
)

if not exist "%SOURCE_EXE%" (
    echo ERROR: Blowfish.exe not found: "%SOURCE_EXE%"
    exit /b 1
)

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to create install directory "%INSTALL_DIR%".
    exit /b 1
)

set "INSTALL_MODE=installed"
if exist "%INSTALL_EXE%" (
    set "INSTALL_MODE=updated"
    attrib -R "%INSTALL_EXE%" >nul 2>&1
)

copy /Y "%SOURCE_EXE%" "%INSTALL_EXE%" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy Blowfish.exe to "%INSTALL_EXE%".
    exit /b 1
)

reg add "HKCU\Software\Classes\*\shell\Blowfish" /v "MUIVerb" /t REG_SZ /d "Blowfish" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish" /v "SubCommands" /t REG_SZ /d "" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish" /v "Icon" /t REG_SZ /d "\"%INSTALL_EXE%\",-101" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Encrypt" /v "MUIVerb" /t REG_SZ /d "Encrypt" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Encrypt" /v "Icon" /t REG_SZ /d "\"%INSTALL_EXE%\",-102" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Encrypt\command" /ve /t REG_SZ /d "\"%INSTALL_EXE%\" --shell-encrypt \"%%1\"" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Decrypt" /v "MUIVerb" /t REG_SZ /d "Decrypt" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Decrypt" /v "Icon" /t REG_SZ /d "\"%INSTALL_EXE%\",-103" /f >nul
reg add "HKCU\Software\Classes\*\shell\Blowfish\shell\Decrypt\command" /ve /t REG_SZ /d "\"%INSTALL_EXE%\" --shell-decrypt \"%%1\"" /f >nul

if errorlevel 1 (
    echo ERROR: Failed to write registry keys.
    exit /b 1
)

if /i "%INSTALL_MODE%"=="updated" (
    echo Updated "%INSTALL_EXE%" to a newer build.
) else (
    echo Installed "%INSTALL_EXE%".
)
echo Context menu installed.
exit /b 0
