@echo off
setlocal
set "SOURCE_EXE=%~dp0Blowfish.exe"
set "INSTALL_DIR=%ProgramFiles%\Blowfish"
set "INSTALL_EXE=%INSTALL_DIR%\Blowfish.exe"

net session >nul 2>&1
if errorlevel 1 (
    if /i "%~1"=="__elevated" (
        echo ERROR: Administrative privileges are required.
        call :notify "Blowfish install failed" "Administrative privileges are required." "Error"
        exit /b 1
    )

    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '__elevated' -Verb RunAs"
    if errorlevel 1 (
        echo ERROR: Elevation was cancelled or failed.
        call :notify "Blowfish install failed" "Elevation was cancelled or failed." "Error"
        exit /b 1
    )
    exit /b 0
)

if not exist "%SOURCE_EXE%" (
    echo ERROR: Blowfish.exe not found: "%SOURCE_EXE%"
    call :notify "Blowfish install failed" "Blowfish.exe was not found next to install.bat." "Error"
    exit /b 1
)

if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if errorlevel 1 (
    echo ERROR: Failed to create install directory "%INSTALL_DIR%".
    call :notify "Blowfish install failed" "Failed to create the install directory in Program Files." "Error"
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
    call :notify "Blowfish install failed" "Failed to copy Blowfish.exe into Program Files." "Error"
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
    call :notify "Blowfish install failed" "Failed to write the context menu registry keys." "Error"
    exit /b 1
)

call :refresh_shell_icons

if /i "%INSTALL_MODE%"=="updated" (
    echo Updated "%INSTALL_EXE%" to a newer build.
    echo Explorer icon cache refreshed.
    call :notify "Blowfish updated" "Blowfish.exe, context menu, and Explorer icons were refreshed." "Info"
) else (
    echo Installed "%INSTALL_EXE%".
    echo Explorer icon cache refreshed.
    call :notify "Blowfish installed" "Blowfish.exe, context menu, and Explorer icons were refreshed." "Info"
)
echo Context menu installed.
exit /b 0

:refresh_shell_icons
set "IE4UINIT=%SystemRoot%\System32\ie4uinit.exe"
if exist "%IE4UINIT%" (
    "%IE4UINIT%" -ClearIconCache >nul 2>&1
    "%IE4UINIT%" -show >nul 2>&1
)
exit /b 0

:notify
set "NOTIFY_TITLE=%~1"
set "NOTIFY_MESSAGE=%~2"
set "NOTIFY_ICON=%~3"
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAKAEEAZABkAC0AVAB5AHAAZQAgAC0AQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcACgAkAHQAaQB0AGwAZQAgAD0AIAAkAGUAbgB2ADoATgBPAFQASQBGAFkAXwBUAEkAVABMAEUACgAkAG0AZQBzAHMAYQBnAGUAIAA9ACAAJABlAG4AdgA6AE4ATwBUAEkARgBZAF8ATQBFAFMAUwBBAEcARQAKACQAaQBjAG8AbgBOAGEAbQBlACAAPQAgACQAZQBuAHYAOgBOAE8AVABJAEYAWQBfAEkAQwBPAE4ACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4AIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAE4AbwB0AGkAZgB5AEkAYwBvAG4ACgBzAHcAaQB0AGMAaAAgACgAJABpAGMAbwBuAE4AYQBtAGUAKQAgAHsACgAgACAAJwBFAHIAcgBvAHIAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoARQByAHIAbwByAAoAIAAgACAAIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAgAD0AIABbAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAFQAbwBvAGwAVABpAHAASQBjAG8AbgBdADoAOgBFAHIAcgBvAHIACgAgACAAfQAKACAAIAAnAFcAYQByAG4AaQBuAGcAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAB9AAoAIAAgAGQAZQBmAGEAdQBsAHQAIAB7AAoAIAAgACAAIAAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBJAGMAbwBuACAAPQAgAFsAUwB5AHMAdABlAG0ALgBEAHIAYQB3AGkAbgBnAC4AUwB5AHMAdABlAG0ASQBjAG8AbgBzAF0AOgA6AEkAbgBmAG8AcgBtAGEAdABpAG8AbgAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoASQBuAGYAbwAKACAAIAB9AAoAfQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAAVABpAHQAbABlACAAPQAgACQAdABpAHQAbABlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AQgBhAGwAbABvAG8AbgBUAGkAcABUAGUAeAB0ACAAPQAgACQAbQBlAHMAcwBhAGcAZQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAASQBjAG8AbgAgAD0AIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAFYAaQBzAGkAYgBsAGUAIAA9ACAAJAB0AHIAdQBlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AUwBoAG8AdwBCAGEAbABsAG8AbwBuAFQAaQBwACgANQAwADAAMAApAAoAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBNAGkAbABsAGkAcwBlAGMAbwBuAGQAcwAgADUANQAwADAACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBEAGkAcwBwAG8AcwBlACgAKQA= >nul 2>&1
exit /b 0
