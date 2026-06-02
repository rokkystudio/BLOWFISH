cmake_minimum_required(VERSION 3.24)

cmake_policy(SET CMP0091 NEW)

project(Blowfish LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(BLOWFISH_INSTALL_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/install.bat.in")
set(BLOWFISH_UNINSTALL_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/uninstall.bat.in")
set(BLOWFISH_INSTALL_SCRIPT "${CMAKE_BINARY_DIR}/install.bat")
set(BLOWFISH_UNINSTALL_SCRIPT "${CMAKE_BINARY_DIR}/uninstall.bat")

add_executable(Blowfish
    sources/blowfish.cpp
    sources/main.cpp
    sources/app_icon.rc
)

set_target_properties(Blowfish PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

target_include_directories(Blowfish PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sources
)

target_compile_definitions(Blowfish PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(Blowfish PRIVATE
    user32
    bcrypt
)

add_custom_command(
    OUTPUT "${BLOWFISH_INSTALL_SCRIPT}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${BLOWFISH_INSTALL_TEMPLATE}" "${BLOWFISH_INSTALL_SCRIPT}"
    DEPENDS "${BLOWFISH_INSTALL_TEMPLATE}"
    COMMENT "Generating install.bat"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BLOWFISH_UNINSTALL_SCRIPT}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${BLOWFISH_UNINSTALL_TEMPLATE}" "${BLOWFISH_UNINSTALL_SCRIPT}"
    DEPENDS "${BLOWFISH_UNINSTALL_TEMPLATE}"
    COMMENT "Generating uninstall.bat"
    VERBATIM
)

add_custom_target(generate_bat_files
    DEPENDS
        "${BLOWFISH_INSTALL_SCRIPT}"
        "${BLOWFISH_UNINSTALL_SCRIPT}"
)

add_dependencies(Blowfish generate_bat_files)

set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    "${BLOWFISH_INSTALL_SCRIPT}"
    "${BLOWFISH_UNINSTALL_SCRIPT}"
    "generated"
    "${CMAKE_SOURCE_DIR}/build/Blowfish.exe"
    "${CMAKE_SOURCE_DIR}/build/install.bat"
    "${CMAKE_SOURCE_DIR}/build/uninstall.bat"
)

if (MSVC)
    target_compile_options(Blowfish PRIVATE /utf-8 /W4)
endif()

if (MINGW)
    target_link_options(Blowfish PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()
