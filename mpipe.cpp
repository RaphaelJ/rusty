/*
 * Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
 * University of Liege.
 */

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include <arpa/inet.h>  // inet_pton

#include <gxio/mpipe.h> // gxio_mpipe_*

#include <tmc/alloc.h>  // tmc_alloc_map, tmc_alloc_set_home,
                        // tmc_alloc_set_pagesize.
#include <tmc/cpus.h>   // tmc_cpus_get_my_current_cpu, tmc_cpus_set_my_cpu
#include <tmc/task.h>   // tmc_task_die

using namespace std;

// -----------------------------------------------------------------------------

//
// Paramaters.
//

// Number of packet descriptors in the ingress queue.
//
// Could be 128, 512, 2048 or 65536.
static const unsigned int IQUEUE_ENTRIES = GXIO_MPIPE_IQUEUE_ENTRY_512;

// Number of packet descriptors in the egress queue.
//
// Could be 512, 2048, 8192 or 65536.
static const unsigned int EQUEUE_ENTRIES = GXIO_MPIPE_EQUEUE_ENTRY_2048;

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
};

static const array<buffer_info_t, 8> BUFFERS_STACKS = {
    { .size = GXIO_MPIPE_BUFFER_SIZE_128,   .count = 800 }, // ~ 100 KB
    { .size = GXIO_MPIPE_BUFFER_SIZE_256,   .count = 800 }, // ~ 200 KB
    { .size = GXIO_MPIPE_BUFFER_SIZE_512,   .count = 800 }, // ~ 400 KB
    { .size = GXIO_MPIPE_BUFFER_SIZE_1024,  .count = 400 }, // ~ 400 KB
    { .size = GXIO_MPIPE_BUFFER_SIZE_1664,  .count = 400 }, // ~ 650 KB

    // Only relevant if jumbo frames are allowed:
    { .size = GXIO_MPIPE_BUFFER_SIZE_4096,  .count = 0 },
    { .size = GXIO_MPIPE_BUFFER_SIZE_10368, .count = 0 },
    { .size = GXIO_MPIPE_BUFFER_SIZE_16384, .count = 0 },
};

// -----------------------------------------------------------------------------

#ifdef NDEBUG
    #define TCP_MPIPE_DEBUG(MSG, ...)
#else
    #define TCP_MPIPE_DEBUG(MSG, ...)                                          \
            fprintf(stderr, "[DEBUG] " MSG "\n", ##__VA_ARGS__)
#endif

#define DIE(WHY)                                                               \
    do {                                                                       \
        tmc_task_die("[__FILE__:__LINE__] %s\n", (WHY));                       \
    } while (0)

// Parsed CLI arguments.
struct args_t {
    char            *link_name;
    int             instance;   // mPIPE instance which is connected to the
                                // link.
    struct in_addr  ipv4;
};

struct buffer_stack_t {
    buffer_info_t   *info;
    unsigned int    id;
    void            *mem;
    void            *buffer_mem;
}

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
}

bool parse_args(int argc, const char **argv, args_t *args);

void bind_to_current_cpu(void);

int main(int argc, char **argv)
{
    args_t args;
    if (!parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    bind_to_current_cpu();

    mpipe_env_t mpipe_env;
    mpipe_init(&args, mpipe_env);

    mpipe_close(&mpipe_env);

    return EXIT_SUCCESS;
}

void print_usage(const char **argv);

// Parses CLI arguments.
//
// Fails on a malformed command.
bool parse_args(int argc, const char **argv, args_t *args)
{
    if (argc != 3)
        print_usage(argv);

    args->link_name = argv[1];
    args->link_id = gxio_mpipe_link_instance(args->link_name);
    if (args->link_id < 0) {
        fprintf(
            stderr, "%s doesn't exist or is not an mPIPE link\n",
            args->link_name
        );
        print_usage(argv);
        return false;
    }

    if (inet_pton(AF_INET, argv[2], &(args.ipv4)) != 1) {
        fprintf(stderr, "Failed to parse the IPv4.\n");
        print_usage(argv);
        return false;
    }

    return true;
}

void print_usage(const char **argv)
{
    fprintf(stderr, "Usage: %s link ipv4\n", argv[0]);
}

void bind_to_current_cpu(void)
{
    int current_cpu;
    if ((current_cpu = tmc_cpus_get_my_current_cpu()) < 0)
        DIE("tmc_cpus_get_my_current_cpu()");

    if (tmc_cpus_set_my_cpu(current_cpu))
        DIE("tmc_cpus_set_my_cpu()");
}

// Check for errors from GXIO API, which returns negative error codes.
#define VERIFY_GXIO(VAL, WHAT)                                                 \
  do {                                                                         \
    long __val = (long) (VAL);                                                 \
    if (__val < 0)                                                             \
        tmc_task_die(                                                          \
            "[__FILE__:__LINE__] %s: (%ld) %s.\n",                             \
            (WHAT), __val, gxio_strerror(__val)                                \
        );                                                                     \
  } while (0)

// Initializes the given mpipe_env_t using the command line parameters.
//
// Starts the mPIPE driver, allocates a NotifRing and its iqueue wrapper, an
// eDMA ring with its equeue wrapper and a set of buffers with its buffer stack.
//
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
void mpipe_init(const *args_t args, mpipe_env_t *mpipe_env)
{
    int result;

    gxio_mpipe_context_t * const context = &(mpipe_env->context);

    //
    // mPIPE driver
    //

    {
        gxio_mpipe_link_t * const link = &(mpipe_env->link);

        result = gxio_mpipe_init(context, args->instance);
        VERIFY_GXIO(result, "gxio_mpipe_init()");

        result = gxio_mpipe_link_open(link, context, args->link_name, 0);
        VERIFY_GXIO(result, "gxio_mpipe_link_open()");

        // // Enable JUMBO ethernet packets
        // gxio_mpipe_link_set_attr(link, GXIO_MPIPE_LINK_RECEIVE_JUMBO, 1);
    }

    //
    // Ingres queue (NotifRing, NotifGroup, iqueue wrapper and buckets)
    //

    {
        //
        // NotifRing and iqueue wrapper
        //

        // Gets a NotifRing ID.
        // NOTE: multiple rings could be allocated so different threads could be
        // able to process packets in parallel.
        result = gxio_mpipe_alloc_notif_rings(
            mpipe_context, 1 /* count */, 0, 0
        );
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
        tmc_alloc_t alloc = TMC_ALLOC_HOME_HERE;

        // Sets page_size >= ring_size.
        if (tmc_alloc_set_pagesize(&alloc, ring_size) == NULL)
            DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        TCP_MPIPE_DEBUG(
            "Allocating %zu bytes for the NotifRing on a %zu-wide page",
            ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        mpipe_env->notif_ring_mem = tmc_alloc_map(&alloc, ring_size);
        if (mpipe_env->notif_ring_mem == NULL)
            DIE("tmc_alloc_map()");

        assert(mpipe_env->notif_ring_mem & 0xFFF == 0); // ring is 4 KB aligned.

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

        gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_ROUND_ROBIN;
        result = gxio_mpipe_init_notif_group_and_buckets(
            context, mpipe_env->group_id, mpipe_env->ring_id,
            1 /* ring count */, mpipe_env->bucket_id, 1 /* bucket count */,
            GXIO_MPIPE_BUCKET_ROUND_ROBIN /* load-balancing mode */
        );
        VERIFY_GXIO(result, "gxio_mpipe_init_notif_group_and_buckets()");
    }

    //
    // Egress queue
    //

    {
        // Allocates a single eDMA ring ID. Multiple eDMA rings could be used
        // concurrently on the same context/link.
        result = gxio_mpipe_alloc_edma_rings(context, 1 /* count */, 0, 0);
        VERIFY_GXIO(result, "gxio_mpipe_alloc_edma_rings");
        mpipe_env->notif_edma_id = result;

        size_t ring_size = EQUEUE_ENTRIES * sizeof(gxio_mpipe_edesc_t);

        // The eDMA ring must be 4 KB aligned and must reside on a single
        // physically contiguous memory. So we allocate a page sufficiently
        // large to hold it.
        // As only the mPIPE processor and no Tile will read from this memory,
        // and as memory-write are non-blocking in this case, we can benefit
        // from an hash-for-home cache policy.
        // NOTE: test the impact on this policy on performances.
        tmc_alloc_t alloc = TMC_ALLOC_HOME_HASH;

        // Sets page_size >= ring_size.
        if (tmc_alloc_set_pagesize(&alloc, ring_size) == NULL)
            DIE("tmc_alloc_set_pagesize()");

        assert(tmc_alloc_get_pagesize(&alloc) >= ring_size);

        TCP_MPIPE_DEBUG(
            "Allocating %zu bytes for the eDMA ring on a %zu-wide page",
            ring_size, tmc_alloc_get_pagesize(&alloc)
        );

        mpipe_env->edma_ring_mem = tmc_alloc_map(&alloc, ring_size);
        if (mpipe_env->edma_ring_mem == NULL)
            DIE("tmc_alloc_map()");

        assert(mpipe_env->edma_ring_mem & 0xFFF == 0); // ring is 4 KB aligned.

        // Initializes an equeue which uses the eDMA ring memory and the channel
        // associated with the context's link.

        int channel = gxio_mpipe_link_channel(&(mpipe_env->link));

        result = gxio_mpipe_equeue_init(
            &(mpipe_env->equeue), context, mpipe_env->notif_edma_id,
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
        int stack_id = result;

        mpipe_env->buffer_stacks.reserve(n_stacks);

        // Allocates, initializes and registers the memory for each stacks.
        for (buffer_info_t buffer_info : BUFFERS_STACKS) {
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
            tmc_alloc_t alloc = TMC_ALLOC_HOME_HASH;

            // Page size must be at least 64 KB, and must be able to store the
            // entire stack. Moreover, we can we have up to 16 TLB page entries
            // per buffer stack.
            //
            // To minimize the memory space used, we will try to use as much TLB
            // entries as possible with pages larger than the stack and 64 KB.
            size_t min_page_size = max(
                (total_size + 15) / 16, // == (int) ceil(total_size / 16)
                // Page size must be >= 64 KB and >= stack_size
                max(64 * 1024, stack_size)
            );

            if (tmc_alloc_set_pagesize(&alloc, min_page_size) == NULL)
                // NOTE: could fail if there is no page size >= 64 KB.
                DIE("tmc_alloc_set_pagesize()");

            TCP_MPIPE_DEBUG(
                "Allocating %zu bytes for %lu %zu bytes buffers and a %zu "
                "bytes stack on a %zu-wide page", total_size, buffer_info.count,
                buffer_info.size, stack_size, tmc_alloc_get_pagesize(&alloc)
            );

            void *mem = tmc_alloc_map(&alloc, total_size);
            if (mpipe_env->buffers_mem == NULL)
                DIE("tmc_alloc_map()");

            assert(mem & 0xFFFF == 0); // mem is 64 KB aligned.

            // Initializes the buffer stack.

            result = gxio_mpipe_init_buffer_stack(
                context, stack_id, buffer_info.size, mem, total_size, 0
            );
            VERIFY_GXIO(result, "gxio_mpipe_init_buffer_stack()");

            // Registers the buffer pages into the mPIPE's TLB.

            size_t page_size = tmc_alloc_get_pagesize(&alloc);

            for (void *p = mem; p < mem + total_size; p += page_size) {
                result = gxio_mpipe_register_page(
                    context, stack_id, p, page_size, 0
                );
                VERIFY_GXIO(result, "gxio_mpipe_register_page()");
            }

            // Writes buffer descriptors into the stack.

            for (
                int p = mem + stack_size;
                p < mem + total_size;
                p += buffer_info.size
            ) {
                assert(p & 0x7F == 0); // buffer is 128 bytes aligned.

                gxio_mpipe_push_buffer(context, stack_id, p);
            }

            mpipe_env->buffer_stacks.push_back({
                .info       = buffer_info,
                .id         = stack_id,
                .mem        = mem,
                .buffer_mem = mem + stack_size
            });

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

        result = gxio_mpipe_rules_init(rules, context);
        VERIFY_GXIO(result, "gxio_mpipe_rules_init()");

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

#undef VERIFY_GXIO
