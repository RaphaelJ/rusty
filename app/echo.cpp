//
// Echo server. Replies to requests on a port with a copy of the received
// message.
//
// Usage: ./app/echo <link> <ipv4> <TCP port>
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

#include <cstdio>
#include <cstdlib>

#include "driver/cpu.hpp"       // bind_to_dataplane()
#include "driver/mpipe.hpp"     // mpipe_t
#include "util/macros.hpp"      // RUSTY_DEBUG, COLOR_GRN

using namespace std;

using namespace rusty::driver;
using namespace rusty::net;

#define ECHO_COLOR     COLOR_GRN
#define ECHO_DEBUG(MSG, ...)                                                   \
    RUSTY_DEBUG("ECHO", ECHO_COLOR, MSG, ##__VA_ARGS__)

// Parsed CLI arguments.
struct args_t {
    char                    *link_name;
    net_t<ipv4_addr_t>      ipv4_addr;
    mpipe_t::tcp_t::port_t  tcp_port;
    size_t                  n_workers;
};

static void _print_usage(char **argv);

// Parses CLI arguments.
//
// Fails on a malformed command.
static bool _parse_args(int argc, char **argv, args_t *args);

// Used to define empty event handlers.
static void _do_nothing(void);

int main(int argc, char **argv)
{
    args_t args;
    if (!_parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    cpu::bind_to_dataplane(0);

    mpipe_t mpipe(args.link_name, args.ipv4_addr, args.n_workers);

    ECHO_DEBUG(
        "Starts the echo server on interface %s (%s) with %s as IPv4 address "
        "on port %d",
        args.link_name, mpipe_t::ethernet_t::addr_t::to_alpha(mpipe.ether_addr),
        mpipe_t::ipv4_t::addr_t::to_alpha(args.ipv4_addr), args.tcp_port
    );

    mpipe.tcp_listen(
        // On new connection handler.
        args.tcp_port,
        [](mpipe_t::tcp_t::conn_t conn)
        {
            ECHO_DEBUG(
                "New connection from %s:%" PRIu16 " on port %" PRIu16,
                mpipe_t::ipv4_t::addr_t::to_alpha(conn.tcb_id.raddr),
                conn.tcb_id.rport.host(), conn.tcb_id.lport.host()
            );

            mpipe_t::tcp_t::conn_handlers_t handlers;

            handlers.new_data =
                [conn](mpipe_t::cursor_t in) mutable
                {
                    size_t size = in.size();

                    in.read_with(
                        [size](const char *buffer)
                        {
                            ECHO_DEBUG(
                                "Received %zu bytes: %.*s", size, (int) size,
                                buffer
                            );
                        }, size
                    );

                    conn.send(
                        size,
                        [in](size_t offset, mpipe_t::cursor_t out)
                        {
                            in.drop(offset)
                              .take(out.size())
                              .for_each(
                                [&out](const char * buffer, size_t buffer_size)
                                {
                                    out = out.write(buffer, buffer_size);
                                }
                            );
                        },

                        _do_nothing // Does nothing on acknowledgment
                    );
                };

            handlers.remote_close = _do_nothing;

            handlers.close =
                [conn]() mutable
                {
                    // Closes when the remote closes the connection.
                    conn.close();
                };

            handlers.reset = _do_nothing;

            return handlers;
        }
    );

    // Runs the application.
    mpipe.run();

    // Wait for the instance to finish (will not happen).
    mpipe.join();

    return EXIT_SUCCESS;
}

static void _print_usage(char **argv)
{
    fprintf(
        stderr, "Usage: %s <link> <ipv4> <TCP port> <n workers>\n", argv[0]
    );
}

static bool _parse_args(int argc, char **argv, args_t *args)
{
    if (argc != 5) {
        _print_usage(argv);
        return false;
    }

    args->link_name = argv[1];

    struct in_addr in_addr;
    if (inet_aton(argv[2], &in_addr) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        _print_usage(argv);
        return false;
    }
    args->ipv4_addr = ipv4_addr_t::from_in_addr(in_addr);

    args->tcp_port = atoi(argv[3]);

    args->n_workers = atoi(argv[4]);

    return true;
}

static void _do_nothing(void)
{
}

#undef ECHO_COLOR
#undef ECHO_DEBUG
