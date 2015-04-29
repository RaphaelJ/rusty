project (tcp-mpipe)

cmake_minimum_required (VERSION 2.8)

set (CMAKE_CC_FLAGS     "-g -Wall -std=c99")
set (CMAKE_CXX_FLAGS    "-g -Wall -std=c++11")

find_package (Threads REQUIRED)

add_subdirectory (util)
add_subdirectory (driver)
add_subdirectory (net)

include_directories (.)

add_executable (main main.cpp)

target_link_libraries (
    main
    pthread tmc gxio
    driver net util
)
