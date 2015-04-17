//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#ifndef __TCP_MPIPE_ALLOCATOR_HPP__
#define __TCP_MPIPE_ALLOCATOR_HPP__

#include <memory>

#include <tmc/alloc.h>      // tmc_alloc_t, tmc_alloc_*
#include <tmc/mspace.h>     // tmc_mspace_*

#include "common.hpp"

using namespace std;

// Allocator which will use the provided tmc_alloc_t configuration to allocate
// an heap on which it will be able to allocate data.
//
// This can be used to specify how memory of STL containers should be cached on
// the Tilera device.
//
// Multiple threads should be able to allocate/deallocate memory concurrently.
//
// Every allocated data will be freed when the object and all of its copies will
// be destucted. Thus you must at least have one copy of TileAllocator alive to
// be able to use allocated memories.
template <typename T>
struct TileAllocator {
public:
    typedef T value_type;

    // Creates an allocator which uses a tmc_alloc_t initialized with
    // TMC_ALLOC_INIT to allocate pages for the heap.
    inline TileAllocator(void)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        _init_mspace(&alloc);
    }

    // Creates an allocator which uses the given tmc_alloc_t to allocate pages
    // for the heap.
    inline TileAllocator(tmc_alloc_t *alloc)
    {
        _init_mspace(&alloc);
    }

    // Creates an allocator which uses a tmc_alloc_t initialized with
    // TMC_ALLOC_INIT on which tmc_alloc_set_home() with the given home
    // parameter to allocate pages for the heap.
    //
    // home can be:
    //
    // * a CPU number. The memory will be cached on ths CPU.
    // * TMC_ALLOC_HOME_SINGLE. The memory will be cached on a single CPU,
    //   choosen by the operating system.
    // * TMC_ALLOC_HOME_HERE. The memory will be cached on the CPU which called
    //   allocate().
    // * TMC_ALLOC_HOME_TASK. The memory will be cached on the CPU which is
    //   accessing it. The kernel will automatically migrates page between CPUs.
    // * TMC_ALLOC_HOME_HASH. The memory will home cache will be distributed
    //   around via hash-for-home.
    // * TMC_ALLOC_HOME_NONE. The memory will not be cached.
    // * TMC_ALLOC_HOME_INCOHERENT. Memory is incoherent between CPUs, and
    //   requires explicit flush and invalidate to enforce coherence.
    // * TMC_ALLOC_HOME_DEFAULT. Use operating system default.
    inline TileAllocator(int home)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_home(&alloc, home);
        _init_mspace(&alloc);
    }

    // Creates an allocator which uses a tmc_alloc_t initialized with
    // TMC_ALLOC_INIT on which tmc_alloc_set_pagesize() with the given pagesize
    // parameter to allocate pages for the heap.
    //
    // The size is rounded up to the nearest page size. If no single page can
    // hold the given number of bytes, the largest page size is selected, and
    // the method returns NULL.
    inline TileAllocator(size_t pagesize)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_pagesize(&alloc, pagesize);
        _init_mspace(&alloc);
    }

    // Combines TileAllocator(int home) and TileAllocator(size_t pagesize).
    inline TileAllocator(int home, size_t pagesize)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_home(&alloc, home);
        tmc_alloc_set_pagesize(&alloc, pagesize);
        _init_mspace(&alloc);
    }

    // -------------------------------------------------------------------------

    //
    // Allocator methods and operators.
    //

    inline T* allocate(size_t length)
    {
        return (T*) tmc_mspace_malloc(&_mspace, length * sizeof (T));
    }

    inline void deallocate(T* ptr, size_t length)
    {
        tmc_mspace_free(ptr);
    }

    friend inline bool operator==(
        const TileAllocator<T>& a, const TileAllocator<T>& b
    )
    {
        return *(a._mspace) == *(b._mspace);
    }

    friend inline bool operator!=(
        const TileAllocator<T>& a, const TileAllocator<T>& b
    )
    {
        return !(a == b);
    }

private:
    // Uses a shared_ptr to the tmc_mspace with a destructor which frees the
    // memory space once no more TileAllocator are referencing it.

    shared_ptr<tmc_mspace> _mspace;

    inline void _init_mspace(tmc_alloc_t *alloc)
    {
        _mspace = shared_ptr<tmc_mspace>(new tmc_mspace, _free_mspace);
        *_mspace = tmc_mspace_create_special(0, TMC_MSPACE_LOCKED, alloc);
    }

    static void _free_mspace(tmc_mspace *mspace)
    {
        TCP_MPIPE_DEBUG("Freeing mpace as address %zu", (size_t) *mspace); 
        tmc_mspace_destroy(*mspace);
        delete mspace;
    }
};

#endif /* __TCP_MPIPE_ALLOCATOR_HPP__ */
