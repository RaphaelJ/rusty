//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to create and send Ethernet frames.
//

#ifndef __TCP_MPIPE_NET_ETHERNET_HPP__
#define __TCP_MPIPE_NET_ETHERNET_HPP__

#include <cinttypes>
#include <cstring>
#include <functional>

#include <net/ethernet.h>   // ether_addr

#include <gxio/mpipe.h>     // gxio_mpipe_*

#include "driver/buffer.hpp"
#include "driver/mpipe.hpp"
#include "util/macros.hpp"

using namespace std;

using namespace tcp_mpipe::driver;

namespace tcp_mpipe {
namespace net {
namespace ethernet {

#define ETH_DEBUG(MSG, ...) TCP_MPIPE_DEBUG("[ETH] " MSG, ##__VA_ARGS__)

static const struct ether_addr BROADCAST_ADDR =
    { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

// Writes the Ethernet header after the given buffer cursor.
//
// 'dst' and 'ether_type' must be in network byte order.
static buffer::cursor_t _write_header(
    const mpipe::env_t *mpipe_env, buffer::cursor_t cursor,
    struct ether_addr dst, uint16_t ether_type
);

// Pushes the given Ethernet frame with its payload on the egress queue using
// the given fuction to generate the payload.
//
// 'dst' and 'ether_type' must be in network byte order.
inline void send_frame(
    mpipe::env_t *mpipe_env, size_t payload_size,
    ether_addr dst, uint16_t ether_type,
    function<void(buffer::cursor_t)> payload_writer
)
{
    size_t headers_size = sizeof (ether_header),
           frame_size   = headers_size + payload_size;

    ETH_DEBUG(
        "Sends a %zu bytes ethernet frame to %s with type %" PRIu16,
        frame_size, ether_ntoa(&dst), ether_type
    );

    // Writes the header and the payload.

    gxio_mpipe_bdesc_t bdesc = mpipe::alloc_buffer(mpipe_env, frame_size);
    buffer::cursor_t cursor = buffer::cursor_t(&bdesc, frame_size);

    cursor = _write_header(mpipe_env, cursor, dst, ether_type);
    payload_writer(cursor);

    // Creates the egress descriptor.

    gxio_mpipe_edesc_t edesc = { 0 };
    edesc.bound     = 1;            // Last and single descriptor for the trame.
    edesc.hwb       = 1,            // The buffer will be automaticaly freed.
    edesc.xfer_size = frame_size;

    // Sets 'va', 'stack_idx', 'inst', 'hwb', 'size' and 'c'.
    gxio_mpipe_edesc_set_bdesc(&edesc, bdesc); 

    // NOTE: if multiple packets are to be sent, reserve() + put_at() with a
    // single memory barrier should be more efficient.
    gxio_mpipe_equeue_put(&(mpipe_env->equeue), edesc);
}

static buffer::cursor_t _write_header(
    const mpipe::env_t *mpipe_env, buffer::cursor_t cursor,
    struct ether_addr dst, uint16_t ether_type
)
{
    return cursor.write_with<struct ether_header>(
        [=](struct ether_header *hdr) {
            const struct ether_addr *src = &(mpipe_env->link_addr);
            mempcpy(&(hdr->ether_dhost), &dst, sizeof (ether_addr));
            mempcpy(&(hdr->ether_shost), src,  sizeof (ether_addr));
            hdr->ether_type = ether_type;
        }
    );
};

} } } /* namespace tcp_mpipe::net::ethernet */

#endif /* __TCP_MPIPE_NET_ETHERNET_HPP__ */
