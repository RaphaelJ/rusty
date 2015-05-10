include_directories (../)

add_library (net    checksum.cpp)

target_link_libraries (net  util)
