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
#include <memory>               // allocator

#include <arch/cycle.h>         // get_cycle_count()
#include <gxio/mpipe.h>         // gxio_mpipe_*, GXIO_MPIPE_*

#include "driver/allocator.hpp" // tile_allocator_t
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

// Number of buckets that the load balancer uses.
//
// Must be a power of 2 and must be be larger or equal to the number of workers.
static const unsigned int N_BUCKETS         = 1024;

// Number of packet descriptors in the ingress queues. There will be as must
// iqueues as workers.
//
// Could be 128, 512, 2K or 64K.
static const unsigned int IQUEUE_ENTRIES    = GXIO_MPIPE_IQUEUE_ENTRY_512;

// Number of packet descriptors in the egress queue.
//
// Could be 512, 2K, 8K or 64K.
static const unsigned int EQUEUE_ENTRIES    = GXIO_MPIPE_EQUEUE_ENTRY_2K;

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

#ifdef MPIPE_JUMBO_FRAMES
    static const array<buffer_stack_info_t, 8> BUFFERS_STACKS {
#else
    static const array<buffer_stack_info_t, 5> BUFFERS_STACKS {
#endif /* MPIPE_JUMBO_FRAMES */
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_128,   4048), // ~ 512 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_256,   1024), // ~ 256 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_512,   1024), // ~ 512 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_1024,  512),  // ~ 512 KB
    buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_1664,  2048), // ~ 1664 KB

    #ifdef MPIPE_JUMBO_FRAMES
        buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_4096,  128), // ~ 512 KB
        buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_10368, 256), // ~ 2.5 MB
        buffer_stack_info_t(GXIO_MPIPE_BUFFER_SIZE_16384, 128)  // ~ 2 MB
    #endif /* MPIPE_JUMBO_FRAMES */
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

    #ifdef USE_TILE_ALLOCATOR
        typedef tile_allocator_t<char *>                    alloc_t;
    #else
        // Uses the standard allocator.
        typedef allocator<char *>                           alloc_t;
    #endif /* USE_TILE_ALLOCATOR */

    // Each worker thread will be given an mPIPE instance.
    //
    // Each instance contains its own ingress queue. A unique egress queue is
    // however shared between all threads.
    struct instance_t {
        //
        // Member types
        //

        // Cursor which will abstract how the upper (Ethernet) layer will read
        // from and write to memory in mPIPE buffers.
        typedef buffer::cursor_t                cursor_t;

        typedef timer::timer_manager_t<alloc_t> timer_manager_t;

        //
        // Fields
        //

        mpipe_t                                 *parent;
        pthread_t                               thread;

        alloc_t                                 alloc;

        // Dataplane Tile dedicated to the execution of this worker.
        int                                     cpu_id;

        // Ingres queue.
        gxio_mpipe_iqueue_t                     iqueue;
        char                                    *notif_ring_mem;

        // Upper Ethernet data-link layer.
        net::ethernet_t<instance_t, alloc_t>    ethernet;

        timer_manager_t                         timers;

        //
        // Methods
        //

        instance_t(alloc_t _alloc);

        // Starts the n workers threads. The function immediatly returns.
        //
        // Forwards any received packet to the upper (Ethernet) data-link layer.
        void run(void);

        // Sends a packet of the given size on the interface by calling the
        // 'packet_writer' with a cursor corresponding to a buffer allocated
        // memory.
        void send_packet(
            size_t packet_size, function<void(cursor_t)> packet_writer
        );

        // Maximum packet size. Doesn't change after initialization.
        inline size_t max_packet_size(void);

        //
        // Static methods
        //

        // Returns the current TCP sequence number.
        static inline
        net::ethernet_t<instance_t, alloc_t>::ipv4_ethernet_t::tcp_ipv4_t::seq_t
        get_current_tcp_seq(void);

    private:
        // Allocates a buffer from the smallest stack able to hold the requested
        // size.
        gxio_mpipe_bdesc_t _alloc_buffer(size_t size);
    };

    typedef buffer::cursor_t                            cursor_t;

    // Aliases for upper network layer types.
    //
    // This permits the user to refer to network layer types easily, (i.e.
    // 'mpipe_t::ipv4_t::addr_t' to refer to an IPv4 address).

    typedef net::ethernet_t<instance_t, alloc_t>        ethernet_t;
    typedef mpipe_t::ethernet_t::ipv4_ethernet_t        ipv4_t;
    typedef mpipe_t::ethernet_t::arp_ethernet_ipv4_t    arp_ipv4_t;
    typedef mpipe_t::ipv4_t::tcp_ipv4_t                 tcp_t;

    // Allocated resources for a buffer stack.
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

    //
    // Fields
    //

    // Driver
    gxio_mpipe_context_t        context;
    gxio_mpipe_link_t           link;

    // Workers instances.
    //
    // Instances are not directly stored in the vector as the will cache-homed
    // on the Tile core that they run on.
    vector<instance_t *>        instances;

    // Ingres queues
    unsigned int                notif_group_id; // Load balancer group.
    unsigned int                first_bucket_id;

    // Egress queue
    gxio_mpipe_equeue_t         equeue;
    unsigned int                edma_ring_id;
    char                        *edma_ring_mem;

    // Buffers and their stacks. Stacks are sorted by increasing buffer sizes.
    vector<buffer_stack_t>      buffer_stacks;

    // Rules
    gxio_mpipe_rules_t          rules;

    // Equals to 'true' while the 'run()' method is running.
    //
    // Setting this field to false will stop the execution of the 'run()'
    // method.
    bool                        is_running = false;

    net_t<ethernet_t::addr_t>   ether_addr;

    // Maximum packet size. Doesn't change after initialization.
    size_t                      max_packet_size;

    // -------------------------------------------------------------------------

    //
    // Methods
    //

    // Initializes the given mpipe_env_t for the given link.
    //
    // Starts the mPIPE driver, allocates NotifRings and their iqueue wrappers,
    // an eDMA ring with its equeue wrapper and a set of buffer stacks with
    // their buffers.
    //
    // 'first_dataplane_cpu' specifies the number of the first dataplane Tile
    // that can be used. Useful when multiple 'mpipe_t' instances are created
    // and that you don't want them to share the same dataplane Tiles.
    mpipe_t(
        const char *link_name, net_t<ipv4_t::addr_t> ipv4_addr, int n_workers,
        int first_dataplane_cpu = 0,
        vector<arp_ipv4_t::static_entry_t> static_arp_entries
            = vector<arp_ipv4_t::static_entry_t>()
    );

    // Releases mPIPE resources referenced by current mPIPE environment.
    ~mpipe_t(void);

    // Starts the workers and process any received packet.
    //
    // This function doesn't return until a call to 'stop()' is made.
    void run(void);

    // Stops the execution of working threads.
    //
    // This method just sets 'is_running' to 'false'. You should make a call to
    // 'join()' after to wait for threads to finish.
    void stop(void);

    // Waits for threads to finish.
    void join(void);

    //
    // TCP server sockets.
    //

    // Starts listening for TCP connections on the given port.
    //
    // If the port was already in the listen state, replaces the previous
    // callback function.
    //
    // FIXME: the function is not thread safe. DON'T call it when workers are
    // concurrently running.
    void tcp_listen(
        tcp_t::port_t tcp, tcp_t::new_conn_callback_t new_conn_callback
    );

    //
    // TCP client/connected sockets.
    //


private:
    // Allocates a buffer from the smallest stack able to hold the requested
    // size.
    gxio_mpipe_bdesc_t _alloc_buffer(size_t size);

    // Sends a packet of the given size on the interface by calling the
    // 'packet_writer' with a cursor corresponding to a buffer allocated
    // memory.
    void send_packet(
        size_t packet_size, function<void(cursor_t)> packet_writer
    );
};

inline size_t mpipe_t::instance_t::max_packet_size(void)
{
    return this->parent->max_packet_size;
}

inline mpipe_t::tcp_t::seq_t mpipe_t::instance_t::get_current_tcp_seq(void)
{
    // Number of cycles between two increments of the sequence number
    // (~ 4 µs).
    static const cycles_t DELAY = CYCLES_PER_SECOND * 4 / 1000000;

    return mpipe_t::tcp_t::seq_t((uint32_t) get_cycle_count() / DELAY);
}

} } /* namespace tcp_mpipe::driver */

#endif /* __TCP_MPIPE_DRIVER_MPIPE_HPP__ */
