project (mpipe-tcp)

cmake_minimum_required (VERSION 2.8)

set (CMAKE_CC_FLAGS     "-g -Wall -std=c99")
set (CMAKE_CXX_FLAGS    "-g -Wall -std=c++11")

find_package (Threads REQUIRED)

add_executable (main main.cpp   arp.cpp buffer.cpp cpu.cpp mpipe.cpp)
target_link_libraries (main pthread tmc gxio)
