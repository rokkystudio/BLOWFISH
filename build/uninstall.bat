@echo off
setlocal
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

reg delete "HKCU\Software\Classes\*\shell\Blowfish" /f >nul

if exist "%INSTALL_DIR%\" (
    attrib -R "%INSTALL_DIR%\*" /S /D >nul 2>&1
    rmdir /S /Q "%INSTALL_DIR%" >nul 2>&1
    if exist "%INSTALL_DIR%\" (
        echo ERROR: Failed to delete "%INSTALL_DIR%".
        exit /b 1
    )
)

echo Context menu removed and installation files cleaned from Program Files.
exit /b 0
