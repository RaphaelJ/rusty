//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Various pre-processor macros used by the mPIPE driver.
//

#ifndef __TCP_MPIPE_DRIVER_DRIVER_HPP__
#define __TCP_MPIPE_DRIVER_DRIVER_HPP__

#include <gxio/mpipe.h>     // gxio_strerror

#include "util/macros.hpp"

#define DRIVER_COLOR     COLOR_YEL
#define DRIVER_DEBUG(MSG, ...)                                                 \
    TCP_MPIPE_DEBUG("DRIVER", DRIVER_COLOR, MSG, ##__VA_ARGS__)
#define DRIVER_DIE(MSG, ...)                                                   \
    TCP_MPIPE_DIE(  "DRIVER", DRIVER_COLOR, MSG, ##__VA_ARGS__)

// Checks for errors in function which returns -1 and sets errno on failure.
#define VERIFY_ERRNO(VAL, WHAT)                                                \
    do {                                                                       \
        long __val = (long) (VAL);                                             \
        if (__val == -1)                                                       \
            DRIVER_DIE("%s (errno: %d)", (WHAT), errno);                       \
    } while (0)

// Checks for errors from the GXIO API, which returns negative error codes.
#define VERIFY_GXIO(VAL, WHAT)                                                 \
  do {                                                                         \
    long __val = (long) (VAL);                                                 \
    if (__val < 0)                                                             \
        DRIVER_DIE("%s: (%ld) %s", (WHAT), __val, gxio_strerror(__val));       \
  } while (0)

#endif /* __TCP_MPIPE_DRIVER_DRIVER_HPP__ */
