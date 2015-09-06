project (rusty)

# CFLAGS

# Uses the Tilera's memory allocator.
#
# Memory that is required by a single core will be homed on this core.
# Can improve the performances.
add_definitions(-DUSE_TILE_ALLOCATOR)

# Uses Jumbo Ethernet frames if supported by the remote TCP.
#
# Improves the performances but consumes more mPIPE resources.
# add_definitions(-DMPIPE_JUMBO_FRAMES)

# Uses chained mPIPE buffers.
#
# Can improve or decrease performances.
# add_definitions(-DMPIPE_CHAINED_BUFFERS)

# Tells the compiler to generate branch prediction hints.
#
# Can improve performances.
add_definitions(-DBRANCH_PREDICT)

# Disables debug messages and assertions (implies -DNDEBUGMSG).
#
# Increases performances.
add_definitions(-DNDEBUG)

# Disable debug messages.
#
# Increases performances.
add_definitions(-DNDEBUGMSG)

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
