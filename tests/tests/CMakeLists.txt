cmake_minimum_required(VERSION "3.14")

find_package(Check REQUIRED)

include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

add_executable(check_hook check_hook_x64.c)
add_executable(check_peloader check_peloader.c)

target_link_libraries(check_hook PRIVATE ${CHECK_LIBRARIES} pthread hook)
target_link_libraries(check_hook PRIVATE hook)
target_link_libraries(check_hook PRIVATE ${CMAKE_SOURCE_DIR}/../peloader/libpeloader.a)

target_link_libraries(check_peloader PRIVATE ${CHECK_LIBRARIES} pthread hook)
target_link_libraries(check_peloader PRIVATE ${CMAKE_SOURCE_DIR}/../peloader/libpeloader.a)

# Create testing target and redirect its output to `Testing` folder
add_test(NAME check_hook COMMAND check_hook WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
add_test(NAME check_peloader COMMAND check_peloader WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

set_tests_properties(check_hook PROPERTIES TIMEOUT 30)
set_tests_properties(check_peloader PROPERTIES TIMEOUT 30)
