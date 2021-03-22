cmake_minimum_required(VERSION "3.13")
project("hook")

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("zydis")

# Create our libhook static library
add_library("hook" "hook.c")

target_compile_options ( Zydis PUBLIC -m32 )
set_target_properties( hook PROPERTIES LINK_FLAGS -m32 )

# Have CMake link our project executable against Zydis.
target_link_libraries("hook" PRIVATE "Zydis")