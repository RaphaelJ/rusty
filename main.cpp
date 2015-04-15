/*
 * Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
 * University of Liege.
 */

#include <cstdio>
#include <cstdlib>
#include <cinttypes>

#include <arpa/inet.h>      // inet_ntoa, inet_pton
#include <netinet/in.h>     // struct in_addr
#include <net/ethernet.h>   // struct ether_addr

// NOTE: To remove and put in mpipe.cpp
#include <gxio/mpipe.h> // gxio_mpipe_*, GXIO_MPIPE_*

#include "common.h"
#include "cpu.h"
#include "mpipe.h"

using namespace std;

// Parsed CLI arguments.
struct args_t {
    char            *link_name;
    struct in_addr  ipv4;
};

void print_usage(char **argv);

bool parse_args(int argc, char **argv, args_t *args);

int main(int argc, char **argv)
{
    args_t args;
    if (!parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    bind_to_dataplane(0);

    mpipe_env_t mpipe_env;
    mpipe_init(&mpipe_env, args.link_name);

    u_int8_t *hw_addr_octet = mpipe_ether_addr(&mpipe_env).ether_addr_octet;
    TCP_MPIPE_DEBUG(
        "mPIPE driver started on interface %s (%02x:%02x:%02x:%02x:%02x:%02x) "
        "with %s as IPv4",
        args.link_name,
        hw_addr_octet[0], hw_addr_octet[1], hw_addr_octet[2], hw_addr_octet[3],
        hw_addr_octet[4], hw_addr_octet[5], inet_ntoa(args.ipv4)
    );

    while (1) {
        gxio_mpipe_idesc_t idesc;
        gxio_mpipe_iqueue_get(&(mpipe_env.iqueue), &idesc);

        uint16_t ethertype = gxio_mpipe_idesc_get_ethertype(&idesc);
        TCP_MPIPE_DEBUG("Received ethertype %" PRIu16, ethertype);
    }

    mpipe_close(&mpipe_env);

    return EXIT_SUCCESS;
}

void print_usage(char **argv)
{
    fprintf(stderr, "Usage: %s <link> <ipv4>\n", argv[0]);
}

// Parses CLI arguments.
//
// Fails on a malformed command.
bool parse_args(int argc, char **argv, args_t *args)
{
    if (argc != 3) {
        print_usage(argv);
        return false;
    }

    args->link_name = argv[1];

    if (inet_pton(AF_INET, argv[2], &(args->ipv4)) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        print_usage(argv);
        return false;
    }

    return true;
}
