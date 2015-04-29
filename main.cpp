//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#include <cstdio>
#include <cstdlib>
#include <cinttypes>

#include <arpa/inet.h>      // inet_ntoa(), inet_pton()
#include <netinet/in.h>     // in_addr
#include <netinet/ether.h>  // ether_ntoa()
#include <net/ethernet.h>   // ether_addr, ETHERTYPE_*

// NOTE: To remove and put in mpipe.cpp
#include <gxio/mpipe.h>     // gxio_mpipe_*, GXIO_MPIPE_*

#include "driver/allocator.hpp"
#include "driver/cpu.hpp"
#include "driver/mpipe.hpp"
#include "net/arp.hpp"
#include "util/macros.hpp"

using namespace std;

using namespace tcp_mpipe::driver;
using namespace tcp_mpipe::net;
using namespace tcp_mpipe::utils;

// Parsed CLI arguments.
struct args_t {
    char            *link_name;
    struct in_addr  ipv4_addr;
};

static void _print_usage(char **argv);

static bool _parse_args(int argc, char **argv, args_t *args);

int main(int argc, char **argv)
{
    args_t args;
    if (!_parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    cpu::bind_to_dataplane(0);

    mpipe::env_t mpipe_env;
    mpipe::init(&mpipe_env, args.link_name);

    arp::env_t arp_env;
    arp::init(&arp_env, &mpipe_env, args.ipv4_addr);

    TCP_MPIPE_DEBUG(
        "mPIPE driver started on interface %s (%s) with %s as IPv4 address",
        args.link_name, ether_ntoa(&(mpipe_env.link_addr)),
        inet_ntoa(args.ipv4_addr)
    );

    tile_allocator::tile_allocator_t<int> allocator();

    sleep(2);

    struct in_addr dest;
    inet_aton("10.0.2.1", &dest);
    arp::with_ether_addr(
        &arp_env, dest, [=](struct ether_addr addr) {
            TCP_MPIPE_DEBUG("10.0.2.1 is %s", ether_ntoa(&addr));
        }
    );
    arp::with_ether_addr(
        &arp_env, dest, [=](struct ether_addr addr) {
            TCP_MPIPE_DEBUG("10.0.2.1 is %s", ether_ntoa(&addr));
        }
    );

    while (1) {
        gxio_mpipe_idesc_t idesc;
        gxio_mpipe_iqueue_get(&(mpipe_env.iqueue), &idesc);

        if (gxio_mpipe_iqueue_drop_if_bad(&(mpipe_env.iqueue), &idesc)) {
            TCP_MPIPE_DEBUG("invalid Ethernet frame dropped");
            continue;
        }

        uint16_t ether_type = gxio_mpipe_idesc_get_ethertype(&idesc);
        switch (ether_type) {
        case ETHERTYPE_ARP:
            arp::receive_message(&arp_env, mpipe::get_l3_cursor(&idesc));
            // TODO : free the idesc.
            break;
        case ETHERTYPE_IP:
            TCP_MPIPE_DEBUG("Received IP Ethernet frame");
            break;
        default:
            TCP_MPIPE_DEBUG(
                "Received unknown Ethernet frame (Ether type: %" PRIu16 "). "
                "Drop frame.", ether_type
            );
            gxio_mpipe_iqueue_drop(&(mpipe_env.iqueue), &idesc);
        }

            arp::with_ether_addr(
                &arp_env, dest, [=](struct ether_addr addr) {
                    TCP_MPIPE_DEBUG("10.0.2.1 is %s", ether_ntoa(&addr));
                }
            );
    }

    mpipe::close(&mpipe_env);

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

    if (inet_aton(argv[2], &(args->ipv4_addr)) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        _print_usage(argv);
        return false;
    }

    return true;
}
