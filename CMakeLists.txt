project (tcp-mpipe)

# CFLAGS

# Use the Tilera's memory allocator.
# Memory that is required by a single core will be homed on this core.
add_definitions(-DUSE_TILE_ALLOCATOR)

add_definitions(-DMPIPE_JUMBO_FRAMES)

# add_definitions(-DMPIPE_CHAINED_BUFFERS)

add_definitions(-DNDEBUG) # Disable debug messages and assertions.
# add_definitions(-DNDEBUGMSG) # Disable debug messages.

# End of CFLAGS

cmake_minimum_required (VERSION 2.8)

set (CMAKE_CC_FLAGS     "-Wall -std=c99 -O2")
set (CMAKE_CXX_FLAGS    "-Wall -std=c++11 -O2")

find_package (Threads REQUIRED)

include_directories (.)

add_subdirectory (util)
add_subdirectory (net)
add_subdirectory (driver)
add_subdirectory (app)
