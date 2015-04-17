//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#ifndef __TCP_MPIPE_MPIPE_HPP__
#define __TCP_MPIPE_MPIPE_HPP__

#include <array>
#include <vector>

#include <gxio/mpipe.h> // gxio_mpipe_*, GXIO_MPIPE_*

using namespace std;

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

struct buffer_info_t {
    // Could be 128, 256, 512, 1024, 1664, 4096, 10368 or 16384 bytes.
    // 4096, 10368 and 16384 are only relevant if jumbo frames are allowed.
    gxio_mpipe_buffer_size_enum_t   size;

    unsigned long                   count;

    buffer_info_t(gxio_mpipe_buffer_size_enum_t size, unsigned long count)
        : size(size), count(count) { }
};

static const array<buffer_info_t, 8> BUFFERS_STACKS {
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_128,   800), // ~ 100 KB
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_256,   800), // ~ 200 KB
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_512,   800), // ~ 400 KB
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_1024,  400), // ~ 400 KB
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_1664,  400), // ~ 650 KB

    // Only relevant if jumbo frames are allowed:
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_4096,  0),
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_10368, 0),
    buffer_info_t(GXIO_MPIPE_BUFFER_SIZE_16384, 0)
};

// -----------------------------------------------------------------------------

struct buffer_stack_t {
    const buffer_info_t *info;
    unsigned int        id;
    void                *mem;
    void                *buffer_mem;
};

// Contains references to resources needed by the mPIPE API.
//
// NOTE: should probably be allocated on the Tile's cache which uses the iqueue
// and the equeue wrappers.
struct mpipe_env_t {
    // Driver
    gxio_mpipe_context_t    context;
    gxio_mpipe_link_t       link;

    // Ingres
    gxio_mpipe_iqueue_t     iqueue;
    unsigned int            notif_ring_id;
    void                    *notif_ring_mem;

    unsigned int            notif_group_id;
    unsigned int            bucket_id;

    // Egress
    gxio_mpipe_equeue_t     equeue;
    unsigned int            edma_ring_id;
    void                    *edma_ring_mem;

    // Buffers
    vector<buffer_stack_t>  buffer_stacks;

    // Rules
    gxio_mpipe_rules_t      rules;
};

// Initializes the given mpipe_env_t for the given link.
//
// Starts the mPIPE driver, allocates a NotifRing and its iqueue wrapper, an
// eDMA ring with its equeue wrapper and a set of buffler stacks with their
// buffers.
void mpipe_init(mpipe_env_t *mpipe_env, const char *link_name);

// Release mPIPE resources referenced by the given mpipe_env_t.
void mpipe_close(mpipe_env_t *mpipe_env);

// Returns the hardware address of the link related to the given mPIPE
// environment.
struct ether_addr mpipe_ether_addr(const mpipe_env_t *mpipe_env);

#endif /* __TCP_MPIPE_MPIPE_HPP__ */
