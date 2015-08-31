add_executable(echo echo.cpp)

target_link_libraries (
    echo
    pthread tmc gxio
    driver net util
)

# Precomputes the checksums of the files in the root directory.
#
# Improves the performances.
add_definitions(-DUSE_PRECOMPUTED_CHECKSUMS)

add_executable(httpd httpd.cpp)

target_link_libraries (
    httpd
    pthread tmc gxio
    driver net util
)
