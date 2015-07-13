//
// Wrapper over mPIPE functions.
//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Makes initialization of the driver easier and provides an interface for the
// Ethernet layer to use the mPIPE driver.
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

#ifndef __TCP_MPIPE_DRIVER_MPIPE_HPP__
#define __TCP_MPIPE_DRIVER_MPIPE_HPP__

#include <array>
#include <vector>

#include <arch/cycle.h>         // get_cycle_count()
#include <gxio/mpipe.h>         // gxio_mpipe_*, GXIO_MPIPE_*

#include "driver/buffer.hpp"    // cursor_t
#include "driver/timer.hpp"     // timer_manager_t
#include "net/endian.hpp"       // net_t
#include "net/ethernet.hpp"     // ethernet_t

using namespace std;

using namespace tcp_mpipe::net;

namespace tcp_mpipe {
namespace driver {

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

// Contains references to resources needed to use the mPIPE driver.
//
// Provides an interface for the Ethernet layer to interface with the mPIPE
// driver.
//
// NOTE: should probably be allocated on the Tile's cache which uses the iqueue
// and the equeue wrappers.
struct mpipe_t {
    //
    // Member types
    //

    // Cursor which will abstract how the upper (Ethernet) layer will read from
    // and write to memory in mPIPE buffers.
    typedef buffer::cursor_t                    cursor_t;

    typedef timer::timer_manager_t              timer_manager_t;

    // Upper network layers types.
    typedef ethernet_t<mpipe_t>                 ethernet_mpipe_t;
    typedef ethernet_mpipe_t::ipv4_ethernet_t   ipv4_mpipe_t;
    typedef ipv4_mpipe_t::tcp_ipv4_t            tcp_mpipe_t;

    //
    // Fields
    //

    // Driver
    gxio_mpipe_context_t    context;
    gxio_mpipe_link_t       link;

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

    // Maximum packet size. Doesn't change after intialization.
    size_t                  max_packet_size;

    // Buffers and their stacks. Stacks are sorted by increasing buffer sizes.
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
    vector<buffer_stack_t>  buffer_stacks;

    // Rules
    gxio_mpipe_rules_t      rules;

    timer_manager_t         timers;

    // Upper (Ethernet) data-link layer.
    ethernet_mpipe_t        data_link;

    // -------------------------------------------------------------------------

    //
    // Methods
    //

    // Initializes the given mpipe_env_t for the given link.
    //
    // Starts the mPIPE driver, allocates a NotifRing and its iqueue wrapper, an
    // eDMA ring with its equeue wrapper and a set of buffer stacks with their
    // buffers.
    mpipe_t(const char *link_name, net_t<ipv4_mpipe_t::addr_t> ipv4_addr);

    // Starts an infite polling loop on the ingress queue.
    //
    // Forwards any received packet to the upper (Ethernet) data-link layer.
    void run(void);

    // Sends a packet of the given size on the interface by calling the
    // 'packet_writer' with a cursor corresponding to a buffer allocated
    // memory.
    void send_packet(
        size_t packet_size, function<void(cursor_t)> packet_writer
    );

    // Releases mPIPE resources referenced by current mPIPE environment.
    //
    // You must not expect the 'mpipe_t' destructor to call 'close()'.
    // You should always call 'close()' when you're done with mPIPE resources.
    void close(void);

    //
    // Static methods
    //

    // Returns the current TCP sequence number.
    static inline tcp_mpipe_t::seq_t get_current_tcp_seq()
    {
        // Number of cycles between two increments of the sequence number
        // (~ 4 µs).
        static const cycles_t DELAY = CYCLES_PER_SECOND * 4 / 1000000;

        return tcp_mpipe_t::seq_t((uint32_t) get_cycle_count() / DELAY);
    }

private:
    // Allocates a buffer from the smallest stack able to hold the requested
    // size.
    gxio_mpipe_bdesc_t _alloc_buffer(size_t size);
};

} } /* namespace tcp_mpipe::driver */

#endif /* __TCP_MPIPE_DRIVER_MPIPE_HPP__ */
