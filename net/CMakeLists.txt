include_directories (../)

add_library (net    arp.cpp ethernet.cpp)

target_link_libraries (net  driver util)
