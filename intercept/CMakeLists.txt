cmake_minimum_required(VERSION "3.13")
project(hook C)

# set arch variables (default x86)
# to change the ARCH value to x64, pass -DARCH:STRING=x64 as argument to cmake command
set(ARCH "x86" CACHE STRING "user-specified architecture")
set(HOOK_SRC "./src/hook.c")

if(${ARCH} STREQUAL "x64")
    set(HOOK_SRC "./src/hook_x86_64.c")
elseif(NOT ${ARCH} STREQUAL "x86")
    message(FATAL_ERROR "Allowed ARCH values: x86, x64")
endif()

include_directories("./include")
include_directories("../log")

# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
# build subhook as static library and disable tests
option(SUBHOOK_STATIC "" ON)
option(SUBHOOK_TESTS "" OFF)
# force subhook to compile a 32bit library if ARCH == x86
if(${ARCH} STREQUAL "x86")
    option(SUBHOOK_FORCE_32BIT "" ON)
endif()

# Register Zydis and subhook dependencies.
add_subdirectory("zydis")
add_subdirectory("subhook")

# Create our libhook static library
add_library("hook" ${HOOK_SRC})

# change build and linker options based on user-supplied ARCH value
if(${ARCH} STREQUAL "x86")
    target_compile_options ( Zydis PUBLIC -m32 )
    set_target_properties( hook PROPERTIES LINK_FLAGS -m32 )
endif()

# Have CMake link our project executable against Zydis and subhook.
target_link_libraries(hook PRIVATE "Zydis")
target_link_libraries(hook PRIVATE "subhook")
target_link_libraries(hook PRIVATE "x64_dispatcher")