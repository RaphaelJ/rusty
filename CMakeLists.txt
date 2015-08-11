project (rusty)

# CFLAGS

# Use the Tilera's memory allocator.
#
# Memory that is required by a single core will be homed on this core.
# Can improve the performances.
add_definitions(-DUSE_TILE_ALLOCATOR)

# Use Jumbo Ethernet frames.
#
# The remote TCP must also have Jumbo frame enabled.
# Can improve the performances, but the mPIPE processor is not always able to
# handle a full-rate stream with jumbo frames.
# add_definitions(-DMPIPE_JUMBO_FRAMES)

# Disable debug messages and assertions.
# Do not improve performances.
# add_definitions(-DMPIPE_CHAINED_BUFFERS)

# Disable debug messages and assertions.
add_definitions(-DNDEBUG)

# Disable debug messages.
# add_definitions(-DNDEBUGMSG)

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
