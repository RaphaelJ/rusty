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
#include <cinttypes>

#include <arpa/inet.h>      // inet_aton(), inet_ntoa()
#include <net/ethernet.h>   // ether_addr
#include <netinet/in.h>     // in_addr
#include <netinet/ether.h>  // ether_ntoa()

// NOTE: To remove and put in mpipe.cpp
#include <gxio/mpipe.h>     // gxio_mpipe_*, GXIO_MPIPE_*

#include "driver/allocator.hpp"
#include "driver/cpu.hpp"
#include "driver/mpipe.hpp"
#include "net/arp.hpp"
#include "net/endian.hpp"
#include "net/ethernet.hpp"
#include "net/ipv4.hpp"
#include "util/macros.hpp"

using namespace std;

using namespace tcp_mpipe::driver;
using namespace tcp_mpipe::net;
using namespace tcp_mpipe::utils;

#define MAIN_COLOR     COLOR_GRN
#define MAIN_DEBUG(MSG, ...)                                                   \
    TCP_MPIPE_DEBUG("MAIN", MAIN_COLOR, MSG, ##__VA_ARGS__)

// Parsed CLI arguments.
struct args_t {
    char                *link_name;
    net_t<ipv4_addr_t>  ipv4_addr;
};

static void _print_usage(char **argv);

static bool _parse_args(int argc, char **argv, args_t *args);

int main(int argc, char **argv)
{
    args_t args;
    if (!_parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    cpu::bind_to_dataplane(0);

    mpipe_t mpipe(args.link_name, args.ipv4_addr);

    MAIN_DEBUG(
        "Starts the mPIPE driver interface %s (%s) with %s as IPv4 address",
        args.link_name,
        ethernet_t<mpipe_t>::addr_t::to_alpha(mpipe.data_link.addr),
        ipv4_t<ethernet_t<mpipe_t>>::addr_t::to_alpha(args.ipv4_addr)
    );

    sleep(2);

    mpipe.run();

    tile_allocator::tile_allocator_t<int> allocator();

//     struct in_addr dest;
//     inet_aton("10.0.2.1", &dest);
//     arp::with_ether_addr(
//         &arp_env, dest, [=](struct ether_addr addr) {
//             MAIN_DEBUG("10.0.2.1 is %s", ether_ntoa(&addr));
//         }
//     );
//     arp::with_ether_addr(
//         &arp_env, dest, [=](struct ether_addr addr) {
//             MAIN_DEBUG("10.0.2.1 is %s", ether_ntoa(&addr));
//         }
//     );

    mpipe.close();

    return EXIT_SUCCESS;
}

static void _print_usage(char **argv)
{
    fprintf(stderr, "Usage: %s <link> <ipv4>\n", argv[0]);
}

// Parses CLI arguments.
//
// Fails on a malformed command.
static bool _parse_args(int argc, char **argv, args_t *args)
{
    if (argc != 3) {
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

    return true;
}

#undef MAIN_COLOR
#undef MAIN_DEBUG

