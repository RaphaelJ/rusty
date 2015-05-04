include_directories (../)

add_library (net    ethernet.cpp ipv4.cpp)

target_link_libraries (net  util)
