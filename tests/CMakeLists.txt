cmake_minimum_required(VERSION 3.14)
project(loadlibrary_tests C)

if (NOT EXISTS "${PROJECT_SOURCE_DIR}/data/testdll.dll")
    message(FATAL_ERROR "The test file testdll.dll is not present in the following directory: ${PROJECT_SOURCE_DIR}/data.
    Please, build the testdll (VS2019) solution you find in ${PROJECT_SOURCE_DIR}/third_party and move the generated
    dll in the ${PROJECT_SOURCE_DIR}/data directory.")
elseif(NOT EXISTS "${PROJECT_SOURCE_DIR}/data/mpengine.dll")
    message(FATAL_ERROR "The test file mpclient.dll is not present in the following directory: ${PROJECT_SOURCE_DIR}/data.
    Please, download it and move it.")
endif ()

# Custom cmake modules
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories("../peloader")

# include hook.h
include_directories("../intercept/include")
include_directories("../intercept/subhook")

# Enable x86_64 testing
enable_testing()
add_subdirectory(tests)

add_subdirectory(../intercept intercept_dir)

set(CMAKE_C_STANDARD 99)

add_executable(stub_exe main.c)
