cmake_minimum_required(VERSION 3.24)

cmake_policy(SET CMP0091 NEW)

project(Blowfish LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(BLOWFISH_PUBLISH_DIR "${CMAKE_SOURCE_DIR}/build")
file(MAKE_DIRECTORY "${BLOWFISH_PUBLISH_DIR}")

file(GLOB CRYPTOPP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/*.cpp"
)

list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/test\\.cpp$")
list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/bench.*\\.cpp$")
list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/validat.*\\.cpp$")
list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/datatest\\.cpp$")
list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/regtest.*\\.cpp$")
list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/fipsalgt\\.cpp$")

add_library(cryptopp STATIC
    ${CRYPTOPP_SOURCES}
)

target_include_directories(cryptopp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/sources
)

target_compile_definitions(cryptopp PRIVATE
    NOMINMAX
)

add_executable(Blowfish
    sources/main.cpp
    sources/app_icon.rc
)

target_compile_definitions(Blowfish PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(Blowfish PRIVATE
    user32
    cryptopp
)

add_custom_target(publish ALL
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${BLOWFISH_PUBLISH_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E remove_directory "${BLOWFISH_PUBLISH_DIR}/icons"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${BLOWFISH_PUBLISH_DIR}/install_context_menu.bat"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${BLOWFISH_PUBLISH_DIR}/uninstall_context_menu.bat"
    COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:Blowfish>" "${BLOWFISH_PUBLISH_DIR}/Blowfish.exe"
    COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_BINARY_DIR}/install.bat" "${BLOWFISH_PUBLISH_DIR}/install.bat"
    COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_BINARY_DIR}/uninstall.bat" "${BLOWFISH_PUBLISH_DIR}/uninstall.bat"
    DEPENDS Blowfish
    COMMENT "Publishing Blowfish.exe to ${BLOWFISH_PUBLISH_DIR}"
)

file(GENERATE
    OUTPUT "${CMAKE_BINARY_DIR}/install.bat"
    CONTENT [=[
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
taskkill /IM explorer.exe /F >nul 2>&1
start "" explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
exit /b 0

:notify
set "NOTIFY_TITLE=%~1"
set "NOTIFY_MESSAGE=%~2"
set "NOTIFY_ICON=%~3"
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAKAEEAZABkAC0AVAB5AHAAZQAgAC0AQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcACgAkAHQAaQB0AGwAZQAgAD0AIAAkAGUAbgB2ADoATgBPAFQASQBGAFkAXwBUAEkAVABMAEUACgAkAG0AZQBzAHMAYQBnAGUAIAA9ACAAJABlAG4AdgA6AE4ATwBUAEkARgBZAF8ATQBFAFMAUwBBAEcARQAKACQAaQBjAG8AbgBOAGEAbQBlACAAPQAgACQAZQBuAHYAOgBOAE8AVABJAEYAWQBfAEkAQwBPAE4ACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4AIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAE4AbwB0AGkAZgB5AEkAYwBvAG4ACgBzAHcAaQB0AGMAaAAgACgAJABpAGMAbwBuAE4AYQBtAGUAKQAgAHsACgAgACAAJwBFAHIAcgBvAHIAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoARQByAHIAbwByAAoAIAAgACAAIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAgAD0AIABbAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAFQAbwBvAGwAVABpAHAASQBjAG8AbgBdADoAOgBFAHIAcgBvAHIACgAgACAAfQAKACAAIAAnAFcAYQByAG4AaQBuAGcAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAB9AAoAIAAgAGQAZQBmAGEAdQBsAHQAIAB7AAoAIAAgACAAIAAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBJAGMAbwBuACAAPQAgAFsAUwB5AHMAdABlAG0ALgBEAHIAYQB3AGkAbgBnAC4AUwB5AHMAdABlAG0ASQBjAG8AbgBzAF0AOgA6AEkAbgBmAG8AcgBtAGEAdABpAG8AbgAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoASQBuAGYAbwAKACAAIAB9AAoAfQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAAVABpAHQAbABlACAAPQAgACQAdABpAHQAbABlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AQgBhAGwAbABvAG8AbgBUAGkAcABUAGUAeAB0ACAAPQAgACQAbQBlAHMAcwBhAGcAZQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAASQBjAG8AbgAgAD0AIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAFYAaQBzAGkAYgBsAGUAIAA9ACAAJAB0AHIAdQBlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AUwBoAG8AdwBCAGEAbABsAG8AbwBuAFQAaQBwACgANQAwADAAMAApAAoAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBNAGkAbABsAGkAcwBlAGMAbwBuAGQAcwAgADUANQAwADAACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBEAGkAcwBwAG8AcwBlACgAKQA= >nul 2>&1
exit /b 0
]=]
)

file(GENERATE
    OUTPUT "${CMAKE_BINARY_DIR}/uninstall.bat"
    CONTENT [=[
@echo off
setlocal
set "INSTALL_DIR=%ProgramFiles%\Blowfish"
set "INSTALL_EXE=%INSTALL_DIR%\Blowfish.exe"

net session >nul 2>&1
if errorlevel 1 (
    if /i "%~1"=="__elevated" (
        echo ERROR: Administrative privileges are required.
        call :notify "Blowfish uninstall failed" "Administrative privileges are required." "Error"
        exit /b 1
    )

    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '__elevated' -Verb RunAs"
    if errorlevel 1 (
        echo ERROR: Elevation was cancelled or failed.
        call :notify "Blowfish uninstall failed" "Elevation was cancelled or failed." "Error"
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
        call :notify "Blowfish uninstall failed" "Failed to delete the Program Files directory." "Error"
        exit /b 1
    )
)

call :refresh_shell_icons

echo Context menu removed and installation files cleaned from Program Files.
echo Explorer icon cache refreshed.
call :notify "Blowfish removed" "Context menu, installed files, and Explorer icons were refreshed." "Info"
exit /b 0

:refresh_shell_icons
set "IE4UINIT=%SystemRoot%\System32\ie4uinit.exe"
if exist "%IE4UINIT%" (
    "%IE4UINIT%" -ClearIconCache >nul 2>&1
    "%IE4UINIT%" -show >nul 2>&1
)
taskkill /IM explorer.exe /F >nul 2>&1
start "" explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
exit /b 0

:notify
set "NOTIFY_TITLE=%~1"
set "NOTIFY_MESSAGE=%~2"
set "NOTIFY_ICON=%~3"
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand QQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAKAEEAZABkAC0AVAB5AHAAZQAgAC0AQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcACgAkAHQAaQB0AGwAZQAgAD0AIAAkAGUAbgB2ADoATgBPAFQASQBGAFkAXwBUAEkAVABMAEUACgAkAG0AZQBzAHMAYQBnAGUAIAA9ACAAJABlAG4AdgA6AE4ATwBUAEkARgBZAF8ATQBFAFMAUwBBAEcARQAKACQAaQBjAG8AbgBOAGEAbQBlACAAPQAgACQAZQBuAHYAOgBOAE8AVABJAEYAWQBfAEkAQwBPAE4ACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4AIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAE4AbwB0AGkAZgB5AEkAYwBvAG4ACgBzAHcAaQB0AGMAaAAgACgAJABpAGMAbwBuAE4AYQBtAGUAKQAgAHsACgAgACAAJwBFAHIAcgBvAHIAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoARQByAHIAbwByAAoAIAAgACAAIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAgAD0AIABbAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAFQAbwBvAGwAVABpAHAASQBjAG8AbgBdADoAOgBFAHIAcgBvAHIACgAgACAAfQAKACAAIAAnAFcAYQByAG4AaQBuAGcAJwAgAHsACgAgACAAIAAgACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALgBTAHkAcwB0AGUAbQBJAGMAbwBuAHMAXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoAVwBhAHIAbgBpAG4AZwAKACAAIAB9AAoAIAAgAGQAZQBmAGEAdQBsAHQAIAB7AAoAIAAgACAAIAAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBJAGMAbwBuACAAPQAgAFsAUwB5AHMAdABlAG0ALgBEAHIAYQB3AGkAbgBnAC4AUwB5AHMAdABlAG0ASQBjAG8AbgBzAF0AOgA6AEkAbgBmAG8AcgBtAGEAdABpAG8AbgAKACAAIAAgACAAJABiAGEAbABsAG8AbwBuAEkAYwBvAG4AIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFcAaQBuAGQAbwB3AHMALgBGAG8AcgBtAHMALgBUAG8AbwBsAFQAaQBwAEkAYwBvAG4AXQA6ADoASQBuAGYAbwAKACAAIAB9AAoAfQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAAVABpAHQAbABlACAAPQAgACQAdABpAHQAbABlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AQgBhAGwAbABvAG8AbgBUAGkAcABUAGUAeAB0ACAAPQAgACQAbQBlAHMAcwBhAGcAZQAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAEIAYQBsAGwAbwBvAG4AVABpAHAASQBjAG8AbgAgAD0AIAAkAGIAYQBsAGwAbwBvAG4ASQBjAG8AbgAKACQAbgBvAHQAaQBmAHkASQBjAG8AbgAuAFYAaQBzAGkAYgBsAGUAIAA9ACAAJAB0AHIAdQBlAAoAJABuAG8AdABpAGYAeQBJAGMAbwBuAC4AUwBoAG8AdwBCAGEAbABsAG8AbwBuAFQAaQBwACgANQAwADAAMAApAAoAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBNAGkAbABsAGkAcwBlAGMAbwBuAGQAcwAgADUANQAwADAACgAkAG4AbwB0AGkAZgB5AEkAYwBvAG4ALgBEAGkAcwBwAG8AcwBlACgAKQA= >nul 2>&1
exit /b 0
]=]
)

if (MSVC)
    target_compile_options(Blowfish PRIVATE /utf-8 /W4)
    target_compile_options(cryptopp PRIVATE /utf-8)
endif()

if (MINGW)
    file(GLOB CRYPTOPP_SIMD_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/*_simd.cpp"
    )
    file(GLOB CRYPTOPP_SSE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/*_sse.cpp"
    )
    file(GLOB CRYPTOPP_AVX_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/*_avx.cpp"
    )

    # Crypto++ SIMD/AVX translation units require explicit ISA flags with MinGW.
    set_source_files_properties(${CRYPTOPP_SIMD_SOURCES}
        PROPERTIES COMPILE_OPTIONS "-mssse3;-msse4.2;-mpclmul;-maes"
    )
    set_source_files_properties(${CRYPTOPP_SSE_SOURCES}
        PROPERTIES COMPILE_OPTIONS "-mssse3"
    )
    set_source_files_properties(${CRYPTOPP_AVX_SOURCES}
        PROPERTIES COMPILE_OPTIONS "-mavx2"
    )

    # Some Crypto++ SIMD files use Intel SHA intrinsics (shaintrin.h).
    # They require explicit -msha with MinGW.
    set_property(SOURCE
        "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/sha_simd.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/sources/cryptopp/shacal2_simd.cpp"
        APPEND PROPERTY COMPILE_OPTIONS -msha
    )

    target_link_options(Blowfish PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()
