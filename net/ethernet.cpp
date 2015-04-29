//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to receive and send Ethernet frames.
//

#include <cinttypes>
#include <cstring>
#include <functional>

#include <net/ethernet.h>   // ether_addr, ETHERTYPE_*
#include <netinet/ether.h>  // ether_ntoa

#include <gxio/mpipe.h>     // gxio_mpipe_*

#include "driver/buffer.hpp"
#include "driver/mpipe.hpp"
#include "net/arp.hpp"
#include "util/macros.hpp"

#include "net/ethernet.hpp"

using namespace tcp_mpipe::driver;
using namespace tcp_mpipe::net;

namespace tcp_mpipe {
namespace net {
namespace ethernet {

#define ETH_DEBUG(MSG, ...) TCP_MPIPE_DEBUG("[ETH] " MSG, ##__VA_ARGS__)

const struct ether_addr BROADCAST_ADDR =
    { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

void receive_frame(
    mpipe::env_t *mpipe_env, arp::env_t *arp_env, gxio_mpipe_idesc_t *idesc
)
{
    if (gxio_mpipe_iqueue_drop_if_bad(&(mpipe_env->iqueue), idesc)) {
        ETH_DEBUG("Invalid Ethernet frame dropped");
        return;
    }

    uint16_t ether_type = gxio_mpipe_idesc_get_ethertype(idesc);
    switch (ether_type) {
    case ETHERTYPE_ARP:
        arp::receive_message(arp_env, mpipe::get_l3_cursor(idesc));
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
        gxio_mpipe_iqueue_drop(&(mpipe_env->iqueue), idesc);
    }
}

// Writes the Ethernet header after the given buffer cursor.
//
// 'dst' and 'ether_type' must be in network byte order.
static buffer::cursor_t _write_header(
    const mpipe::env_t *mpipe_env, buffer::cursor_t cursor,
    struct ether_addr dst, uint16_t ether_type
);

void send_frame(
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

} } } /* namespace tcp_mpipe::drivers:cpu */
