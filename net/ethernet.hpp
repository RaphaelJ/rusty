//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to receive and send Ethernet frames.
//

#ifndef __TCP_MPIPE_NET_ETHERNET_HPP__
#define __TCP_MPIPE_NET_ETHERNET_HPP__

#include <cinttypes>
#include <functional>

#include <net/ethernet.h>   // ether_addr

#include "driver/buffer.hpp"
#include "driver/mpipe.hpp"
#include "net/arp.hpp"

using namespace std;

using namespace tcp_mpipe::driver;
using namespace tcp_mpipe::net;

namespace tcp_mpipe {
namespace net {
namespace ethernet {

extern const struct ether_addr BROADCAST_ADDR;

// Processes an Ethernet frame described by the given ingress descriptor.
void receive_frame(
    mpipe::env_t *mpipe_env, arp::env_t *arp_env, gxio_mpipe_idesc_t *idesc
);

// Pushes the given Ethernet frame with its payload on the egress queue using
// the given fuction to generate the payload.
//
// 'dst' and 'ether_type' must be in network byte order.
void send_frame(
    mpipe::env_t *mpipe_env, size_t payload_size,
    ether_addr dst, uint16_t ether_type,
    function<void(buffer::cursor_t)> payload_writer
);

} } } /* namespace tcp_mpipe::net::ethernet */

#endif /* __TCP_MPIPE_NET_ETHERNET_HPP__ */
