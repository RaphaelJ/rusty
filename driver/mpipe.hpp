//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Wrappers for mPIPE functions. Makes initialization of the driver easier.
//

#ifndef __TCP_MPIPE_DRIVER_MPIPE_HPP__
#define __TCP_MPIPE_DRIVER_MPIPE_HPP__

#include <array>
#include <vector>

#include <gxio/mpipe.h> // gxio_mpipe_*, GXIO_MPIPE_*

#include "driver/buffer.hpp"

using namespace std;

namespace tcp_mpipe {
namespace driver {
namespace mpipe {

// -----------------------------------------------------------------------------

//
// Paramaters.
//

// Number of packet descriptors in the ingress queue.
//
// Could be 128, 512, 2K or 64K.
static const unsigned int IQUEUE_ENTRIES = GXIO_MPIPE_IQUEUE_ENTRY_512;

// Number of packet descriptors in the egress queue.
//
// Could be 512, 2K, 8K or 64K.
static const unsigned int EQUEUE_ENTRIES = GXIO_MPIPE_EQUEUE_ENTRY_2K;

// mPIPE buffer stacks.
//
// Gives the number of buffers and the buffer sizes for each buffer stack.
//
// mPIPE only allows 32 buffer stacks to be used at the same time.
//
// NOTE: Knowing the average and standard deviation of received/emitted packets
// and the optimal cache usage, the most efficient buffer sizes could be
// computed.

struct buffer_stack_info_t {
    // Could be 128, 256, 512, 1024, 1664, 4096, 10368 or 16384 bytes.
    // 4096, 10368 and 16384 are only relevant if jumbo frames are allowed.
    gxio_mpipe_buffer_size_enum_t   size;

    unsigned long                   count;

    buffer_stack_info_t(gxio_mpipe_buffer_size_enum_t size, unsigned long count)
        : size(size), count(count) { }
};

static const array<buffer_stack_info_t, 8> BUFFERS_STACKS {
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_128,   800), // ~ 100 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_256,   800), // ~ 200 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_512,   800), // ~ 400 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_1024,  400), // ~ 400 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_1664,  400), // ~ 650 KB

    // Only relevant if jumbo frames are allowed:
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_4096,  0),
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_10368, 0),
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_16384, 0)
};

// -----------------------------------------------------------------------------

//
// mPIPE environment
//

struct buffer_stack_t {
    const buffer_stack_info_t   *info;
    unsigned int                id;

    // Result of 'gxio_mpipe_buffer_size_enum_to_buffer_size(info->size)'.
    size_t                      buffer_size;

    // First byte of the buffer stack.
    char                        *mem;
    // Packet buffer memory allocated just after the buffer stack.
    char                        *buffer_mem;

    // Number of bytes allocated for the buffer stack and its buffers.
    size_t                      mem_size;
};

// Contains references to resources needed by the mPIPE API.
//
// NOTE: should probably be allocated on the Tile's cache which uses the iqueue
// and the equeue wrappers.
struct env_t {
    // Driver
    gxio_mpipe_context_t    context;
    gxio_mpipe_link_t       link;

    // Ethernet address of the network interface (in network byte order).
    struct ether_addr       link_addr;

    // Ingres
    gxio_mpipe_iqueue_t     iqueue;
    unsigned int            notif_ring_id;
    char                    *notif_ring_mem;

    unsigned int            notif_group_id;
    unsigned int            bucket_id;

    // Egress
    gxio_mpipe_equeue_t     equeue;
    unsigned int            edma_ring_id;
    char                    *edma_ring_mem;

    // Buffers and their stacks. Stacks are sorted by increasing buffer sizes.
    vector<buffer_stack_t>  buffer_stacks;

    // Rules
    gxio_mpipe_rules_t      rules;
};

// -----------------------------------------------------------------------------

//
// Functions
//

// Initializes the given mpipe_env_t for the given link.
//
// Starts the mPIPE driver, allocates a NotifRing and its iqueue wrapper, an
// eDMA ring with its equeue wrapper and a set of buffer stacks with their
// buffers.
void init(env_t *mpipe_env, const char *link_name);

// Releases mPIPE resources referenced by the given mpipe_env_t.
void close(env_t *mpipe_env);

// Returns a network layer (L3) packet cursor for the given 'idesc'.
inline buffer::cursor_t get_l3_cursor(gxio_mpipe_idesc_t *idesc)
{
    return buffer::cursor_t(idesc).drop(gxio_mpipe_idesc_get_l3_offset(idesc));
}

// Allocates a buffer from the smallest stack able to hold the requested size.
gxio_mpipe_bdesc_t alloc_buffer(env_t *env, size_t size);

// Frees the buffer to its original stack.
inline void free_buffer(env_t *env, gxio_mpipe_bdesc_t bdesc)
{
    gxio_mpipe_push_buffer_bdesc(&(env->context), bdesc);
}

} } } /* namespace tcp_mpipe::driver::mpipe */

#endif /* __TCP_MPIPE_DRIVER_MPIPE_HPP__ */
