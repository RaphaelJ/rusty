include_directories (../)

add_library (driver     buffer.cpp cpu.cpp mpipe.cpp)

target_link_libraries (driver   util)