//
// Various pre-processor macros.
//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef __RUSTY_UTILS_MACROS_HPP__
#define __RUSTY_UTILS_MACROS_HPP__

//
// Branch prediction hints.
//

#ifdef BRANCH_PREDICT
    #define LIKELY(x)       __builtin_expect(!!(x), 1)
    #define UNLIKELY(x)     __builtin_expect((x), 0)
#else
    #define LIKELY(x)
    #define UNLIKELY(x)
#endif /* BRANCH_PREDICT */

//
// Terminal colors
//

#define COLOR_RED       "\033[31;1m"
#define COLOR_GRN       "\033[32;1m"
#define COLOR_YEL       "\033[33;1m"
#define COLOR_BLU       "\033[34;1m"
#define COLOR_MAG       "\033[35;1m"
#define COLOR_CYN       "\033[36;1m"

#define COLOR_BOLD      "\033[1m"

#define COLOR_RESET     "\033[0m"

//
// Logging messages
//

// There is three levels of log messages: debug, error and die, each associated
// with their respective 'RUSTY_*' macros.
//
// * 'RUSTY_DEBUG()' should be used for information messages during normal
//   operations, such as events. These messages will only be displayed when
//   NDEBUG is not defined.
// * 'RUSTY_ERROR()' should be used for unexpected but recoverable events,
//   such as the reception of an invalid packet.
// * 'RUSTY_DIE()' should be used for unexpected and unrecoverable events,
//   such as a failled memory allocation. The macro immediately stops the
//   application after displaying the message by calling 'exit()' with
//   'EXIT_FAILURE' as status code.
//
// Each macro displays the error message with the module name and where it has
// been called. Each module have an associated color to make messages easier to
// read.
//
// The passed message could use be formatted as in 'printf' and an arbritary
// number of arguments could be given to the macros.

#ifdef NDEBUG
    #define RUSTY_DEBUG(MODULE, COLOR, MSG, ...)
#elif NDEBUGMSG
    #define RUSTY_DEBUG(MODULE, COLOR, MSG, ...)
#else
    #define RUSTY_DEBUG(MODULE, COLOR, MSG, ...)                               \
        do {                                                                   \
            fprintf(                                                           \
                stderr, "%-20s%-20s" MSG,                                      \
                "[" COLOR_GRN "DEBUG" COLOR_RESET "]",                         \
                "[" COLOR MODULE COLOR_RESET "]",                              \
                ##__VA_ARGS__                                                  \
            );                                                                 \
            fprintf(stderr, " (" __FILE__ ":%d)\n", __LINE__);                 \
        } while (0)
#endif

#define RUSTY_ERROR(MODULE, COLOR, MSG, ...)                                   \
    do {                                                                       \
        fprintf(                                                               \
            stderr, "%-20s%-20s" COLOR_BOLD MSG,                               \
            "[" COLOR_YEL "ERROR" COLOR_RESET "]",                             \
            "[" COLOR MODULE COLOR_RESET "]",                                  \
            ##__VA_ARGS__                                                      \
        );                                                                     \
        fprintf(stderr, " (" __FILE__ ":%d)" COLOR_RESET "\n", __LINE__);      \
    } while (0)

#define RUSTY_DIE(MODULE, COLOR, MSG, ...)                                     \
    do {                                                                       \
        fprintf(                                                               \
            stderr, "%-20s%-20s" COLOR_BOLD MSG,                               \
            "[" COLOR_RED "DIE" COLOR_RESET "]",                               \
            "[" COLOR MODULE COLOR_RESET "]",                                  \
            ##__VA_ARGS__                                                      \
        );                                                                     \
        fprintf(stderr, " (" __FILE__ ":%d)" COLOR_RESET "\n", __LINE__);      \
        exit(EXIT_FAILURE);                                                    \
    } while (0)


#endif /* __RUSTY_UTILS_MACROS_HPP__ */
