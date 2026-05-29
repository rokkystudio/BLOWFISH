cmake_minimum_required(VERSION 3.24)

cmake_policy(SET CMP0091 NEW)

project(BlowfishTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(BlowfishTool
        sources/main.cpp
        sources/app.cpp
        sources/blowfish.cpp
        sources/file_cipher.cpp
        sources/text_encoding.cpp
        sources/win_key_dialog.cpp
)

target_compile_definitions(BlowfishTool PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)

target_link_libraries(BlowfishTool PRIVATE
        user32
        bcrypt
)

if (MSVC)
    target_compile_options(BlowfishTool PRIVATE /utf-8 /W4)
endif()

if (MINGW)
    target_link_options(BlowfishTool PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()