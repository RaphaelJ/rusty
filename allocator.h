//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#include <memory>

// Allocator which will use the provided tmc_alloc_t configuration to allocate
// data.
//
// This can be used to specify how memory of STL containers should be cached on
// the Tilera device.
//
// NOTE: The current allocator will allocate a new full page for each call to
// allocate(). A better allocator should reuse unused spaces in previously
// allocated pages.
template <class T>
struct TileAllocator {
private:
    TileAllocator();

public:
    typedef T value_type;

    tmc_alloc_t alloc;

    // Creates an allocator which uses TMC_ALLOC_INIT as tmc_alloc_t
    // configuration.
    inline TileAllocator(void)
    {
        alloc = TMC_ALLOC_INIT;
    }

    // Creates an allocator which will use the given tmc_alloc_t configuration.
    inline TileAllocator(tmc_alloc_t _alloc)
    {
        alloc = _alloc;
    }

    // Equivalent to calling TileAllocator(void) and then set_home().
    inline TileAllocator(int home) : TileAllocator()
    {
        set_home(home);
    }

    // Equivalent to calling TileAllocator(void) and then set_pagesize().
    inline TileAllocator(sizet pagesize) : TileAllocator()
    {
        set_pagesize(home);
    }
    }

    // Equivalent to calling TileAllocator(void) and then set_pagesize().
    inline TileAllocator(sizet pagesize) : TileAllocator()
    {
        set_pagesize(home);
    }

    // -------------------------------------------------------------------------

    // 
    // Modifies the inner tmc_alloc_t.
    //

    // Calls tmc_alloc_set_home() on the inner tmc_alloc_t.
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
    inline void set_home(int home)
    {
        tmc_alloc_set_home(&alloc, home);
    }

    // Calls tmc_alloc_set_pagesize() on the inner tmc_alloc_t.
    //
    // The size is rounded up to the nearest page size. If no single page can
    // hold the given number of bytes, the largest page size is selected, and
    // the method returns NULL.
    inline void set_pagesize(size_t size)
    {
        tmc_alloc_set_home(&alloc, home);
    }

    // -------------------------------------------------------------------------

    //
    // Allocator methods.
    //

    inline T* allocate(size_t length)
    {
        return (T*) tmc_alloc_map(&alloc, length);
    }

    void deallocate(T* ptr, size_t length)
    {
        tmc_alloc_unmap(ptr, length);
    }
};
