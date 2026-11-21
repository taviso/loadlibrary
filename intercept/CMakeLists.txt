cmake_minimum_required(VERSION 3.13)
project(hook C)

set(ARCH "x64" CACHE STRING "Target architecture")
if(NOT ARCH STREQUAL "x64")
    message(FATAL_ERROR "The CMake hook backend supports x64 only; build x86 with the top-level Makefile")
endif()

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(SUBHOOK_STATIC ON CACHE BOOL "" FORCE)
set(SUBHOOK_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(zydis)
add_subdirectory(subhook)

add_library(hook STATIC src/hook_x86_64.c)
target_include_directories(hook PRIVATE include ../log)
target_link_libraries(hook PRIVATE Zydis subhook)
