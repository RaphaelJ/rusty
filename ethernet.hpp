//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to create and send Ethernet frames.
//

#ifndef __TCP_MPIPE_ETHERNET_HPP__
#define __TCP_MPIPE_ETHERNET_HPP__

#include <cstring>
#include <functional>

#include <net/ethernet.h>   // ether_addr

#include <gxio/mpipe.h>     // gxio_mpipe_*

#include "buffer.hpp"
#include "mpipe.hpp"

using namespace std;

namespace tcp_mpipe {

static inline buffer_cursor_t _ethernet_write_header(
    buffer_cursor_t cursor,  ether_addr src,  ether_addr dst,
    uint16_t ether_type
);

inline void ethernet_send_frame(
    mpipe_env_t *mpipe_env, size_t payload_size,
    ether_addr src, ether_addr dst, uint16_t ether_type,
    function<void(buffer_cursor_t)> payload_writer
)
{
    size_t headers_size = sizeof (ether_header),
           frame_size   = headers_size + payload_size;

    // Writes the header and the payload.

    gxio_mpipe_bdesc_t bdesc = mpipe_alloc_buffer(mpipe_env, frame_size);
    buffer_cursor_t cursor = buffer_cursor_t(&bdesc, frame_size);

    cursor = _ethernet_write_header(cursor, src, dst, ether_type);
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

static inline buffer_cursor_t _ethernet_write_header(
    buffer_cursor_t cursor, ether_addr src, ether_addr dst,
    uint16_t ether_type
)
{
    return cursor.write_with<struct ether_header>(
        [=](struct ether_header *hdr) {
            mempcpy(&(hdr->ether_dhost), &dst, sizeof (ether_addr));
            mempcpy(&(hdr->ether_shost), &src, sizeof (ether_addr));
            hdr->ether_type = ether_type;
        }
    );
};

} /* namespace tcp_mpipe */

#endif /* __TCP_MPIPE_ETHERNET_HPP__ */
