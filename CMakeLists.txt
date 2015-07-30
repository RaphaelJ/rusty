project (tcp-mpipe)

# CFLAGS

add_definitions(-DMPIPE_JUMBO_FRAMES)
# add_definitions(-DNDEBUG)

# End of CFLAGS

cmake_minimum_required (VERSION 2.8)

set (CMAKE_CC_FLAGS     "-g -Wall -std=c99")
set (CMAKE_CXX_FLAGS    "-g -Wall -std=c++11")

find_package (Threads REQUIRED)

include_directories (.)

add_subdirectory (util)
add_subdirectory (net)
add_subdirectory (driver)
add_subdirectory (app)
