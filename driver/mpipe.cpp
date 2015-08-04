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

#include <algorithm>            // sort()
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <utility>              // min()

#include <net/ethernet.h>       // struct ether_addr
#include <pthread.h>            // pthread_*

#include <gxio/mpipe.h>         // gxio_mpipe_*
#include <tmc/alloc.h>          // tmc_alloc_map(), tmc_alloc_set_home(),
                                // tmc_alloc_set_pagesize().
#include <tmc/mem.h>            // tmc_mem_prefetch()
#include <tmc/cpus.h>           // tmc_cpus_*

#include "driver/driver.hpp"    // VERIFY_ERRNO, VERIFY_GXIO
#include "driver/buffer.hpp"    // cursor_t
#include "net/endian.hpp"       // net_t
#include "net/ethernet.hpp"     // ethernet_t

#include "driver/mpipe.hpp"

using namespace std;

using namespace tcp_mpipe::net;

namespace tcp_mpipe {
namespace driver {

// Returns the hardware address of the link related to the given mPIPE
// environment (in network byte order).
static net_t<mpipe_t::ethernet_t::addr_t> _ether_addr(gxio_mpipe_link_t *link);

void mpipe_t::instance_t::run(void)
{
    int result;

    // Binds the instance to its dataplane CPU.

    result = tmc_cpus_set_my_cpu(this->cpu_id);
    VERIFY_ERRNO(result, "tmc_cpus_set_my_cpu()");

    #ifdef DEBUG_DATAPLANE
        // Put dataplane tiles in "debug" mode. Interrupts other than page
        // faults will generate a kernel stacktrace.
        result = set_dataplane(DP_DEBUG);
        VERIFY_ERRNO(result, "set_dataplane()");
    #endif

    // Polling loop over the packet queue. Tries to executes timers between
    // polling attempts.

    while (LIKELY(this->parent->is_running)) {
        this->timers.tick();

        gxio_mpipe_idesc_t idesc;

        result = gxio_mpipe_iqueue_try_get(&this->iqueue, &idesc);

        if (result == GXIO_MPIPE_ERR_IQUEUE_EMPTY) // Queue is empty. Retries.
            continue;

        if (gxio_mpipe_iqueue_drop_if_bad(&this->iqueue, &idesc)) {
            DRIVER_DEBUG("Invalid packet dropped");
            continue;
        }

        // Initializes a buffer cursor which starts at the Ethernet header and
        // stops at the end of the packet.
        //
        // The buffer will be freed when the cursor will be destructed.
        cursor_t cursor(&this->parent->context, &idesc, true);
        cursor = cursor.drop(gxio_mpipe_idesc_get_l2_offset(&idesc));

        tmc_mem_prefetch(cursor.current, cursor.current_size);

        DRIVER_DEBUG("Receives a %zu bytes packet", cursor.size());

        this->ethernet.receive_frame(cursor);
    }
}

void mpipe_t::instance_t::send_packet(
    size_t packet_size, function<void(cursor_t)> packet_writer
)
{
    assert(packet_size <= this->parent->max_packet_size);

    DRIVER_DEBUG("Sends a %zu bytes packet", packet_size);

    // Allocates a buffer and executes the 'packet_writer' on its memory.
    gxio_mpipe_bdesc_t bdesc = this->parent->_alloc_buffer(packet_size);

    // Allocates an unmanaged cursor, which will not desallocate the buffer when
    // destr
    cursor_t cursor(&this->parent->context, &bdesc, packet_size, false);
    packet_writer(cursor);

    // Creates the egress descriptor.

    gxio_mpipe_edesc_t edesc = { 0 };
    edesc.bound     = 1;            // Last and single descriptor for the trame.
    edesc.hwb       = 1,            // The buffer will be automaticaly freed.
    edesc.xfer_size = packet_size;

    // Sets 'va', 'stack_idx', 'inst', 'hwb', 'size' and 'c'.
    gxio_mpipe_edesc_set_bdesc(&edesc, bdesc); 

    // NOTE: if multiple packets are to be sent, reserve() + put_at() with a
    // single memory barrier should be more efficient.
    gxio_mpipe_equeue_put(&this->parent->equeue, edesc);
}

// We use multiple NotigRings linked to the same NotifGroup to enable some
// kind of load balancing: with multiple NotifRings, each related to a distinct
// worker thread, the hardware load-balancer will classify packets by their flow
// (IP addresses, ports, ...) by worker.
mpipe_t::mpipe_t(
    const char *link_name, net_t<ipv4_t::addr_t> ipv4_addr, int n_workers
) : instances(n_workers)
{
    assert(n_workers > 0);
    assert((unsigned int) n_workers <= N_BUCKETS);

    int result;

    gxio_mpipe_context_t * const context = &this->context;

    //
    // mPIPE driver.
    //
    // Tries to create an context for the mPIPE instance of the given link.
    //

    {
        gxio_mpipe_link_t * const link = &this->link;

        result = gxio_mpipe_link_instance(link_name);
        VERIFY_GXIO(result, "gxio_mpipe_link_instance()");
        int instance_id = result;

        result = gxio_mpipe_init(context, instance_id);
        VERIFY_GXIO(result, "gxio_mpipe_init()");

        result = gxio_mpipe_link_open(link, context, link_name, 0);
        VERIFY_GXIO(result, "gxio_mpipe_link_open()");

        #ifdef MPIPE_JUMBO_FRAMES
            // Enable JUMBO ethernet packets
            gxio_mpipe_link_set_attr(link, GXIO_MPIPE_LINK_RECEIVE_JUMBO, 1);
        #endif
    }

    //
    // Checks if there is enough dataplane Tiles for the requested number of
    // workers.
    //

    {
        // Finds dataplane Tiles.
        cpu_set_t dataplane_cpu_set;
        result = tmc_cpus_get_dataplane_cpus(&dataplane_cpu_set);
        VERIFY_ERRNO(result, "tmc_cpus_get_dataplane_cpus()");

        int count = tmc_cpus_count(&dataplane_cpu_set);
        if (n_workers > count) {
            DRIVER_DIE(
                "There is not enough dataplane Tiles for the requested number "
                "of workers (%u requested, having %u)", n_workers, count
            );
        }

        for (int i = 0; i < n_workers; i++) {
            instance_t *instance = &this->instances[i];

            result = tmc_cpus_find_nth_cpu(&dataplane_cpu_set, i);
            VERIFY_GXIO(result, "tmc_cpus_find_nth_cpu()");
            instance->cpu_id = result;
        }
    }

    //
    // Ingres queues.
    //
    // Creates an iqueue and a notification ring for each worker, and a single
    // notification group with its buckets.
    //

    {
        //
        // Creates a NotifRing and an iqueue wrapper for each worker.
        //

        result = gxio_mpipe_alloc_notif_rings(context, n_workers, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_notif_rings()");
        unsigned int first_ring_id = result;

        tmc_alloc_t alloc = TMC_ALLOC_INIT;

        size_t ring_size = IQUEUE_ENTRIES * sizeof (gxio_mpipe_idesc_t);

        // Sets page_size >= ring_size.
        if (tmc_alloc_set_pagesize(&alloc, ring_size) == NULL)
            DRIVER_DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        for (int i = 0; i < n_workers; i++) {
            instance_t *instance = &this->instances[i];

            unsigned int ring_id = first_ring_id + i;

            // Allocates a NotifRing for each worker.
            //
            // The NotifRing must be 4 KB aligned and must reside on a single
            // physically contiguous memory. So we allocate a page sufficiently
            // large to hold it. This page holding the notifications descriptors
            // will reside on the current Tile's cache.
            //
            // Allocated pages are cache-homed on the worker's Tile.

            tmc_alloc_set_home(&alloc,  instance->cpu_id);

            instance->notif_ring_mem = (char *) tmc_alloc_map(
                &alloc, ring_size
            );
            if (instance->notif_ring_mem == NULL)
                DRIVER_DIE("tmc_alloc_map()");

            // ring is 4 KB aligned.
            assert(((intptr_t) instance->notif_ring_mem & 0xFFF) == 0);

            // Initializes an iqueue for the worker.

            result = gxio_mpipe_iqueue_init(
                &instance->iqueue, context, ring_id, instance->notif_ring_mem,
                ring_size, 0
            );
            VERIFY_GXIO(result, "gxio_mpipe_iqueue_init()");
        }

        DRIVER_DEBUG(
            "Allocated %u x %zu bytes for the NotifRings on a %zu bytes pages",
            n_workers, ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        //
        // Create a single NotifGroup and a set of buckets
        //

        result = gxio_mpipe_alloc_notif_groups(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_notif_groups()");
        this->notif_group_id = result;

        result = gxio_mpipe_alloc_buckets(context, N_BUCKETS, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_buckets()");
        this->first_bucket_id = result;

        // Initialize the NotifGroup and its buckets. Assigns the single
        // NotifRing to the group.

        result = gxio_mpipe_init_notif_group_and_buckets(
            context, this->notif_group_id, first_ring_id,
            n_workers /* ring count */, this->first_bucket_id, N_BUCKETS,
            // Load-balancing mode: packets of a same flow go to the same
            // bucket.
            GXIO_MPIPE_BUCKET_STATIC_FLOW_AFFINITY
        );
        VERIFY_GXIO(result, "gxio_mpipe_init_notif_group_and_buckets()");
    }

    //
    // Egress queue.
    //
    // Initializes a single eDMA ring with its equeue wrapper.
    //

    {
        // Allocates a single eDMA ring ID. Multiple eDMA rings could be used
        // concurrently on the same context/link.
        result = gxio_mpipe_alloc_edma_rings(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_edma_rings");
        this->edma_ring_id = result;

        size_t ring_size = EQUEUE_ENTRIES * sizeof(gxio_mpipe_edesc_t);

        // The eDMA ring must be 1 KB aligned and must reside on a single
        // physically contiguous memory. So we allocate a page sufficiently
        // large to hold it.
        // As only the mPIPE hardware and no Tile will read from this memory,
        // and as memory-write are non-blocking in this case, we can benefit
        // from an hash-for-home cache policy.
        // NOTE: test the impact on this policy on performances.
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);

        // Sets page_size >= ring_size.
        if (tmc_alloc_set_pagesize(&alloc, ring_size) == NULL)
            DRIVER_DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        DRIVER_DEBUG(
            "Allocating %zu bytes for the eDMA ring on a %zu bytes page",
            ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        this->edma_ring_mem = (char *) tmc_alloc_map(&alloc, ring_size);
        if (this->edma_ring_mem == NULL)
            DRIVER_DIE("tmc_alloc_map()");

        // ring is 1 KB aligned.
        assert(((intptr_t) this->edma_ring_mem & 0x3FF) == 0);

        // Initializes an equeue which uses the eDMA ring memory and the channel
        // associated with the context's link.

        int channel = gxio_mpipe_link_channel(&this->link);

        result = gxio_mpipe_equeue_init(
            &this->equeue, context, this->edma_ring_id,
            channel, this->edma_ring_mem, ring_size, 0
        );
        VERIFY_GXIO(result, "gxio_gxio_equeue_init()");
    }

    //
    // Buffer stacks and buffers
    //
    // Initializes a buffer stack and a set of buffers for each non-empty stack
    // in BUFFERS_STACKS.
    //

    {
        // Counts the number of non-empty buffer stacks.
        int n_stacks = 0;
        for (const buffer_stack_info_t& stack_info : BUFFERS_STACKS) {
            if (stack_info.count > 0)
                n_stacks++;
        }

        result = gxio_mpipe_alloc_buffer_stacks(context, n_stacks, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_buffer_stacks()");
        unsigned int stack_id = result;

        this->buffer_stacks.reserve(n_stacks);

        // Allocates, initializes and registers the memory for each stacks.
        for (const buffer_stack_info_t& stack_info : BUFFERS_STACKS) {
            // Skips unused buffer types.
            if (stack_info.count <= 0)
                continue;

            // First we need to compute the exact memory usage of the stack
            // and its associated buffers, then we allocates a set of pages to
            // hold them.
            //
            // Packet buffer memory is allocated after the buffer stack.
            // Buffer stack is required to be 64K aligned on a contiguous
            // memory, so we allocate it at the beginning of a page of at least
            // 64 KB. Buffer memory is required to be 128 byte aligned, so we
            // add a padding after the stack.

            size_t stack_size = gxio_mpipe_calc_buffer_stack_bytes(
                stack_info.count
            );

            // Adds a padding to have a 128 bytes aligned address for the packet
            // buffer memory.
            stack_size += -(long) stack_size & (128 - 1);

            size_t buffer_size = gxio_mpipe_buffer_size_enum_to_buffer_size(
                stack_info.size
            );

            size_t total_size = stack_size + stack_info.count * buffer_size;

            // Uses the distributed caching mechanism for packet data because of
            // being too large to fit in a single Tile local (L2) cache.
            //
            // tmc_mem_prefetch() could be used before accessing a buffer to
            // fetch the buffer into the local cache.
            tmc_alloc_t alloc = TMC_ALLOC_INIT;
            tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HASH);

            // Page size must be at least 64 KB, and must be able to store the
            // entire stack. Moreover, we can we have up to 16 TLB page entries
            // per buffer stack.
            //
            // To minimize the memory space used, we will try to use as much TLB
            // entries as possible with pages larger than the stack and 64 KB.
            size_t min_page_size = max({
                (total_size + 15) / 16, // == (int) ceil(total_size / 16)
                (size_t) 64 * 1024,     // == 64 KB
                stack_size
            });

            if (tmc_alloc_set_pagesize(&alloc, min_page_size) == NULL)
                // NOTE: could fail if there is no page size >= 64 KB.
                DRIVER_DIE("tmc_alloc_set_pagesize()");

            DRIVER_DEBUG(
                "Allocating %lu x %zu bytes buffers (%zu bytes) and a %zu "
                "bytes stack on %zu x %zu bytes page(s)",
                stack_info.count, buffer_size, total_size, stack_size,
                (total_size + 1) / tmc_alloc_get_pagesize(&alloc), 
                tmc_alloc_get_pagesize(&alloc)
            );

            char *mem = (char *) tmc_alloc_map(&alloc, total_size);
            if (mem == NULL)
                DRIVER_DIE("tmc_alloc_map()");

            assert(((intptr_t) mem & 0xFFFF) == 0); // mem is 64 KB aligned.

            // Initializes the buffer stack.

            result = gxio_mpipe_init_buffer_stack(
                context, stack_id, stack_info.size, mem, stack_size, 0
            );
            VERIFY_GXIO(result, "gxio_mpipe_init_buffer_stack()");

            // Registers the buffer pages into the mPIPE's TLB.

            size_t page_size = tmc_alloc_get_pagesize(&alloc);

            for (char *p = mem; p < mem + total_size; p += page_size) {
                result = gxio_mpipe_register_page(
                    context, stack_id, p, page_size, 0
                );
                VERIFY_GXIO(result, "gxio_mpipe_register_page()");
            }

            // Writes buffer descriptors into the stack.

            for (
                char *p = mem + stack_size;
                p < mem + total_size;
                p += buffer_size
            ) {
                // buffer is 128 bytes aligned.
                assert(((size_t) p & 0x7F) == 0);

                gxio_mpipe_push_buffer(context, stack_id, p);
            }

            // Registers the stack resources in the environment.

            buffer_stack_t buffer_stack = {
                &stack_info, stack_id, buffer_size,
                mem, mem + stack_size, total_size
            };

            this->buffer_stacks.push_back(buffer_stack);

            stack_id++;
        }

        // Sorts 'this->buffer_stacks' by increasing buffer sizes.

        sort(
            this->buffer_stacks.begin(), this->buffer_stacks.end(),
            [](const buffer_stack_t& a, const buffer_stack_t& b) {
                return a.info->size < b.info->size;
            }
        );

        max_packet_size = this->buffer_stacks.back().buffer_size;

        #ifndef MPIPE_JUMBO_FRAMES
            gxio_mpipe_link_set_attr(&link, GXIO_MPIPE_LINK_RECEIVE_JUMBO, 1);

            gxio_mpipe_equeue_set_snf_size(&this->equeue, max_packet_size);
        #else 
            max_packet_size = min((size_t) 1500, max_packet_size);
        #endif /* MPIPE_JUMBO_FRAMES */

        DRIVER_DEBUG("Maximum packet size: %zu bytes", max_packet_size);
    }

    //
    // Classifier rules
    //
    // Defines a single rule that match every packet to the unique bucket we
    // created.
    //
    // See UG527-Application-Libraries-Reference-Manual.pdf, page 215.
    //

    {
        gxio_mpipe_rules_t *rules = &this->rules;
        gxio_mpipe_rules_init(rules, context);

        result = gxio_mpipe_rules_begin(
            rules, this->first_bucket_id, N_BUCKETS, nullptr
        );
        VERIFY_GXIO(result, "gxio_mpipe_rules_begin()");

        result = gxio_mpipe_rules_commit(rules);
        VERIFY_GXIO(result, "gxio_mpipe_rules_commit()");
    }

    //
    // Initializes the network protocols stacks.
    //

    {
        this->ether_addr = _ether_addr(&this->link);

        for (instance_t &instance : this->instances) {
            instance.parent = this;
            instance.ethernet.init(
                &instance, &instance.timers, this->ether_addr, ipv4_addr
            );
        }
    }
}

mpipe_t::~mpipe_t(void)
{
    int result;

    // Releases the mPIPE context

    result = gxio_mpipe_link_close(&this->link);
    VERIFY_GXIO(result, "gxio_mpipe_link_close(()");

    result = gxio_mpipe_destroy(&this->context);
    VERIFY_GXIO(result, "gxio_mpipe_destroy()");

    // Releases rings memory

    for (instance_t &instance : this->instances) {
        size_t notif_ring_size = IQUEUE_ENTRIES * sizeof(gxio_mpipe_idesc_t);
        result = tmc_alloc_unmap(instance.notif_ring_mem, notif_ring_size );
        VERIFY_ERRNO(result, "tmc_alloc_unmap()");
    }

    size_t edma_ring_size = EQUEUE_ENTRIES * sizeof(gxio_mpipe_edesc_t);
    result = tmc_alloc_unmap(this->edma_ring_mem, edma_ring_size);
    VERIFY_ERRNO(result, "tmc_alloc_unmap()");

    // Releases buffers memory

    for (const buffer_stack_t& buffer_stack : this->buffer_stacks) {
        result = tmc_alloc_unmap(buffer_stack.mem, buffer_stack.mem_size);
        VERIFY_ERRNO(result, "tmc_alloc_unmap()");
    }
}

// Wrapper over 'instance_t::run()' for 'pthread_create()'.
void *worker_runner(void *);

void mpipe_t::run(void)
{
    this->is_running = true;

    // Starts N-1 worker threads. The last worker will be executed in the
    // current thread.
    for (size_t i = 0; i < instances.size() - 1; i++) {
        instance_t *instance = &this->instances[i];

        int result = pthread_create(
            &instance->thread, nullptr, worker_runner, instance
        );
        VERIFY_PTHREAD(result, "pthread_create()");
    }

    // Executes the last worker in the current thread
    {
        instance_t *last_instance = &this->instances.back();
        last_instance->thread = pthread_self();

        worker_runner(last_instance);
    }

    // Waits for all threads to exit.
    for (size_t i = 0; i < instances.size() - 1; i++) {
        instance_t *instance = &this->instances[i];
        pthread_join(instance->thread, nullptr);
    }
}

void *worker_runner(void *instance_void)
{
    ((mpipe_t::instance_t *) instance_void)->run();
    return nullptr;
}

void mpipe_t::stop(void)
{
    this->is_running = false;
}

// Replicates the call to every worker TCP stack.
//
// 
void mpipe_t::tcp_listen(
    tcp_t::port_t port, tcp_t::new_conn_callback_t new_conn_callback
)
{
    assert(!this->is_running); // FIXME: not thread-safe.

    for (instance_t &instance : this->instances)
        instance.ethernet.ipv4.tcp.listen(port, new_conn_callback);
}


gxio_mpipe_bdesc_t mpipe_t::_alloc_buffer(size_t size)
{
    // Finds the first buffer size large enough to hold the requested buffer.
    for (const buffer_stack_t &stack : this->buffer_stacks) {
        if (stack.buffer_size >= size)
            return gxio_mpipe_pop_buffer_bdesc(&this->context, stack.id);
    }

    // TODO: build a chained buffer if possible.
    DRIVER_DIE("No buffer is sufficiently large to hold the requested size.");
}

static net_t<mpipe_t::ethernet_t::addr_t> _ether_addr(gxio_mpipe_link_t *link)
{
    int64_t addr64 = gxio_mpipe_link_get_attr(link, GXIO_MPIPE_LINK_MAC);

    // Address is in the 48 least-significant bits.
    assert((addr64 & 0xFFFFFFFFFFFF) == addr64);

    // Immediately returns the address in network byte order.
    net_t<mpipe_t::ethernet_t::addr_t> addr;
    addr.net = {
        (uint8_t) (addr64 >> 40),
        (uint8_t) (addr64 >> 32),
        (uint8_t) (addr64 >> 24),
        (uint8_t) (addr64 >> 16),
        (uint8_t) (addr64 >> 8),
        (uint8_t) addr64
    };
    return addr;
}

} } /* namespace tcp_mpipe::driver */
