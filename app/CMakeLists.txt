add_executable(echo echo.cpp)

target_link_libraries (
    echo
    pthread tmc gxio
    driver net util
)
