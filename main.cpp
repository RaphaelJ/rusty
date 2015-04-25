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

#include "allocator.hpp"
#include "arp.hpp"
#include "common.hpp"
#include "cpu.hpp"
#include "mpipe.hpp"

using namespace std;
using namespace tcp_mpipe;

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

    bind_to_dataplane(0);

    mpipe_env_t mpipe_env;
    mpipe_init(&mpipe_env, args.link_name);

    arp_env_t arp_env;
    arp_init(&arp_env, &mpipe_env, args.ipv4_addr);

    TCP_MPIPE_DEBUG(
        "mPIPE driver started on interface %s (%s) with %s as IPv4",
        args.link_name, ether_ntoa(&(arp_env.ether_addr)),
        inet_ntoa(args.ipv4_addr)
    );

    tile_allocator_t<int> allocator();

    while (1) {
        gxio_mpipe_idesc_t idesc;
        gxio_mpipe_iqueue_get(&(mpipe_env.iqueue), &idesc);

        if (gxio_mpipe_iqueue_drop_if_bad(&(mpipe_env.iqueue), &idesc)) {
            TCP_MPIPE_DEBUG("Ethernet frame dropped");
            continue;
        }

        uint16_t ether_type = gxio_mpipe_idesc_get_ethertype(&idesc);
        switch (ether_type) {
        case ETHERTYPE_ARP:
            TCP_MPIPE_DEBUG("Received ARP Ethernet frame");
            arp_receive(&arp_env, mpipe_get_l3_cursor(&idesc));
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
    }

    mpipe_close(&mpipe_env);

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

    if (inet_pton(AF_INET, argv[2], &(args->ipv4_addr)) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        _print_usage(argv);
        return false;
    }

    return true;
}
