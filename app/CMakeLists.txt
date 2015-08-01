add_executable(echo echo.cpp)

target_link_libraries (
    echo
    pthread tmc gxio
    driver net util
)

add_executable(httpd httpd.cpp)

target_link_libraries (
    httpd
    pthread tmc gxio
    driver net util
)
