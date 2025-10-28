cmake_minimum_required(VERSION 3.15)
project(AntivirusScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" ON)

if(MSVC)
    add_compile_options(/W4)
    # Линкуем с CryptoAPI библиотеками
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} advapi32.lib")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} advapi32.lib")
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

add_subdirectory(src/scanner_core)
add_subdirectory(src/scanner_main)

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()