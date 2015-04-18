//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Wrappers for mPIPE functions. Makes initialization of the driver easier.
//

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <gxio/mpipe.h>     // gxio_mpipe_*
#include <net/ethernet.h>   // struct ether_addr
#include <tmc/alloc.h>      // tmc_alloc_map, tmc_alloc_set_home,
                            // tmc_alloc_set_pagesize.

#include "common.hpp"
#include "mpipe.hpp"

using namespace std;

namespace tcp_mpipe {

// Checks for errors from the GXIO API, which returns negative error codes.
#define VERIFY_GXIO(VAL, WHAT)                                                 \
  do {                                                                         \
    long __val = (long) (VAL);                                                 \
    if (__val < 0)                                                             \
        DIE("%s: (%ld) %s", (WHAT), __val, gxio_strerror(__val));              \
  } while (0)

// The NotifRing is being part of a single unique NotifGroup. One single bucket
// is mapped to this NotifGroup.
//
// We could use multiple NotigRings linked to the same NotifGroup to enable some
// kind of load balancing: with more than one NotifRing, each related to a
// distinct thread, the hardware load-balancer will pick the least busy to
// process packet notifications.
//
// NOTE: accepts a pointer to an mpipe_env_t instead of returning a new
// mpipe_env_t so the structure can be efficiently allocated by the caller
// (i.e. on the Tile's cache of the tile which uses the iqueue and equeue
// wrappers).
void mpipe_init(mpipe_env_t *mpipe_env, const char *link_name)
{
    int result;

    gxio_mpipe_context_t * const context = &(mpipe_env->context);

    //
    // mPIPE driver.
    //
    // Tries to create an context for the mPIPE instance of the given link.
    //

    {
        gxio_mpipe_link_t * const link = &(mpipe_env->link);

        result = gxio_mpipe_link_instance(link_name);
        VERIFY_GXIO(result, "gxio_mpipe_link_instance()");
        int instance_id = result;

        result = gxio_mpipe_init(context, instance_id);
        VERIFY_GXIO(result, "gxio_mpipe_init()");

        result = gxio_mpipe_link_open(link, context, link_name, 0);
        VERIFY_GXIO(result, "gxio_mpipe_link_open()");

        // // Enable JUMBO ethernet packets
        // gxio_mpipe_link_set_attr(link, GXIO_MPIPE_LINK_RECEIVE_JUMBO, 1);
    }

    //
    // Ingres queue.
    //
    // Initialized the NotifRing, NotifGroup, iqueue wrapper and the unique
    // bucket.
    //

    {
        //
        // NotifRing and iqueue wrapper
        //

        // Gets a NotifRing ID.
        // NOTE: multiple rings could be allocated so different threads could be
        // able to process packets in parallel.
        result = gxio_mpipe_alloc_notif_rings(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_notif_rings()");
        mpipe_env->notif_ring_id = result;

        // Allocates the NotifRing.
        // The NotifRing must be 4 KB aligned and must reside on a single
        // physically contiguous memory. So we allocate a page sufficiently
        // large to hold it. This page holding the notifications descriptors
        // will reside on the current Tile's cache.
        // NOTE: with multiple rings being associated with different threads, we
        // should allocates the ring on its associated Tile's cache.

        size_t ring_size = IQUEUE_ENTRIES * sizeof(gxio_mpipe_idesc_t);

        // Cache pages on current tile.
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_home(&alloc, TMC_ALLOC_HOME_HERE);

        // Sets page_size >= ring_size.
        if (tmc_alloc_set_pagesize(&alloc, ring_size) == NULL)
            DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        TCP_MPIPE_DEBUG(
            "Allocating %zu bytes for the NotifRing on a %zu bytes page",
            ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        mpipe_env->notif_ring_mem = tmc_alloc_map(&alloc, ring_size);
        if (mpipe_env->notif_ring_mem == NULL)
            DIE("tmc_alloc_map()");

        // ring is 4 KB aligned.
        assert(((size_t) mpipe_env->notif_ring_mem & 0xFFF) == 0);

        // Initializes an iqueue which uses the ring memory and the mPIPE
        // context.

        result = gxio_mpipe_iqueue_init(
            &(mpipe_env->iqueue), context, mpipe_env->notif_ring_id,
            mpipe_env->notif_ring_mem, ring_size, 0
        );
        VERIFY_GXIO(result, "gxio_mpipe_iqueue_init()");

        //
        // NotifGroup and buckets
        //

        // Allocates a single NotifGroup having a single NotifRing.

        result = gxio_mpipe_alloc_notif_groups(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_notif_groups()");
        mpipe_env->notif_group_id = result;

        // Allocates a single bucket. Each paquet will go to this bucket and
        // will be mapped to the single NotigGroup.

        result = gxio_mpipe_alloc_buckets(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_buckets()");
        mpipe_env->bucket_id = result;

        // Initialize the NotifGroup and its buckets. Assigns the single
        // NotifRing to the group.

        result = gxio_mpipe_init_notif_group_and_buckets(
            context, mpipe_env->notif_group_id, mpipe_env->notif_ring_id,
            1 /* ring count */, mpipe_env->bucket_id, 1 /* bucket count */,
            GXIO_MPIPE_BUCKET_ROUND_ROBIN /* load-balancing mode */
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
        mpipe_env->edma_ring_id = result;

        size_t ring_size = EQUEUE_ENTRIES * sizeof(gxio_mpipe_edesc_t);

        // The eDMA ring must be 4 KB aligned and must reside on a single
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
            DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        TCP_MPIPE_DEBUG(
            "Allocating %zu bytes for the eDMA ring on a %zu bytes page",
            ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        mpipe_env->edma_ring_mem = tmc_alloc_map(&alloc, ring_size);
        if (mpipe_env->edma_ring_mem == NULL)
            DIE("tmc_alloc_map()");

        // ring is 4 KB aligned.
        assert(((size_t) mpipe_env->edma_ring_mem & 0xFFF) == 0);

        // Initializes an equeue which uses the eDMA ring memory and the channel
        // associated with the context's link.

        int channel = gxio_mpipe_link_channel(&(mpipe_env->link));

        result = gxio_mpipe_equeue_init(
            &(mpipe_env->equeue), context, mpipe_env->edma_ring_id,
            channel, mpipe_env->edma_ring_mem, ring_size, 0
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
        for (buffer_info_t buffer_info : BUFFERS_STACKS) {
            if (buffer_info.count > 0)
                n_stacks++;
        }

        result = gxio_mpipe_alloc_buffer_stacks(context, n_stacks, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_buffer_stacks()");
        unsigned int stack_id = result;

        mpipe_env->buffer_stacks.reserve(n_stacks);

        // Allocates, initializes and registers the memory for each stacks.
        for (const buffer_info_t& buffer_info : BUFFERS_STACKS) {
            // Skips unused buffer types.
            if (buffer_info.count <= 0)
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
                buffer_info.count
            );

            // Adds a padding to have a 128 bytes aligned address for the packet
            // buffer memory.
            stack_size += -(long)stack_size & (128 - 1);

            size_t buffer_size = gxio_mpipe_buffer_size_enum_to_buffer_size(
                buffer_info.size
            );

            size_t total_size = stack_size + buffer_info.count * buffer_size;

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
                DIE("tmc_alloc_set_pagesize()");

            TCP_MPIPE_DEBUG(
                "Allocating %lu x %zu bytes buffers (%zu bytes) and a %zu "
                "bytes stack on %zu x %zu bytes page(s)",
                buffer_info.count, buffer_size, total_size, stack_size,
                (total_size + 1) / tmc_alloc_get_pagesize(&alloc), 
                tmc_alloc_get_pagesize(&alloc)
            );

            char *mem = (char *) tmc_alloc_map(&alloc, total_size);
            if (mem == NULL)
                DIE("tmc_alloc_map()");

            assert(((size_t) mem & 0xFFFF) == 0); // mem is 64 KB aligned.

            // Initializes the buffer stack.

            result = gxio_mpipe_init_buffer_stack(
                context, stack_id, buffer_info.size, mem, stack_size, 0
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
                &buffer_info,
                stack_id,
                mem,
                mem + stack_size
            };

            mpipe_env->buffer_stacks.push_back(buffer_stack);

            stack_id++;
        }
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
        gxio_mpipe_rules_t *rules = &(mpipe_env->rules);
        gxio_mpipe_rules_init(rules, context);

        result = gxio_mpipe_rules_begin(
            rules, mpipe_env->bucket_id, 1 /* bucket count */, NULL
        );
        VERIFY_GXIO(result, "gxio_mpipe_rules_begin()");

        result = gxio_mpipe_rules_commit(rules);
        VERIFY_GXIO(result, "gxio_mpipe_rules_commit()");
    }
}

void mpipe_close(mpipe_env_t *mpipe_env)
{
    int result = gxio_mpipe_link_close(&(mpipe_env->link));
    VERIFY_GXIO(result, "gxio_mpipe_link_close(()");

    result = gxio_mpipe_destroy(&(mpipe_env->context));
    VERIFY_GXIO(result, "gxio_mpipe_destroy()");
}

struct ether_addr mpipe_ether_addr(const mpipe_env_t *mpipe_env)
{
    int64_t addr = gxio_mpipe_link_get_attr(
        (gxio_mpipe_link_t *) &(mpipe_env->link), GXIO_MPIPE_LINK_MAC
    );

    // Address is in the 48 least-significant bits.
    assert((addr & 0xFFFFFFFFFFFF) == addr);

    return { {
            (uint8_t) (addr >> 40),
            (uint8_t) (addr >> 32),
            (uint8_t) (addr >> 24),
            (uint8_t) (addr >> 16),
            (uint8_t) (addr >> 8),
            (uint8_t) addr
        }
    };
}

} /* namespace tcp_mpipe */

#undef VERIFY_GXIO
