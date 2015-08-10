//
// Defines a C++ STL allocator which wraps the TMC memory management library.
//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
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

#ifndef __TCP_MPIPE_DRIVER_ALLOCATOR_HPP__
#define __TCP_MPIPE_DRIVER_ALLOCATOR_HPP__

#include <memory>           // shared_ptr
#include <utility>          // forward

#include <tmc/alloc.h>      // tmc_alloc_t, tmc_alloc_*
#include <tmc/mspace.h>     // tmc_mspace_*

#include "driver/driver.hpp"

#include <execinfo.h>

using namespace std;

namespace tcp_mpipe {
namespace driver {

// Allocator which will use the provided 'tmc_alloc_t' configuration to allocate
// an heap on which it will be able to allocate data.
//
// This can be used to specify how memory of STL containers should be cached on
// the Tilera device.
//
// Multiple threads should be able to allocate/deallocate memory concurrently.
//
// Every allocated data will be freed when the object and all of its copies will
// be destucted. Thus you must at least have one copy of 'tile_allocator_t'
// alive to be able to use allocated memories.
template <typename T>
struct tile_allocator_t {
    //
    // Member types
    //

    typedef T           value_type;
    typedef T*          pointer;
    typedef const T*    const_pointer;
    typedef T&          reference;
    typedef const T&    const_reference;
    typedef size_t      size_type;

    template<class U>
    struct rebind {
        typedef tile_allocator_t<U> other;
    };

    //
    // Member fields
    //

    // Uses a 'shared_ptr' to the 'tmc_mspace' with a destructor which frees the
    // memory space once no more 'tile_allocator_t' are referencing it.

    shared_ptr<tmc_mspace> mspace;

    //
    // Methods
    //

    // Creates an allocator which uses a tmc_alloc_t initialized with
    // TMC_ALLOC_INIT to allocate pages for the heap.
    inline tile_allocator_t(void)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        _init_mspace(&alloc);
    }

    template <typename U>
    inline tile_allocator_t(const tile_allocator_t<U>& other)
        : mspace(other.mspace)
    {
    }

    // Creates an allocator which uses the given tmc_alloc_t to allocate pages
    // for the heap.
    inline tile_allocator_t(tmc_alloc_t *alloc)
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
    inline tile_allocator_t(int home)
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
    inline tile_allocator_t(size_t pagesize)
    {
        tmc_alloc_t alloc = TMC_ALLOC_INIT;
        tmc_alloc_set_pagesize(&alloc, pagesize);
        _init_mspace(&alloc);
    }

    // Combines 'tile_allocator_t(int home)' and
    // 'tile_allocator_t(size_t pagesize)'.
    inline tile_allocator_t(int home, size_t pagesize)
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

    inline T* address(T& obj)
    {
        return &obj;
    }

    inline T* allocate(size_t length)
    {
        // DRIVER_DEBUG("allocate<%s>(%zu)", typeid (T).name(), length);

        return (T*) tmc_mspace_malloc(*mspace, length * sizeof (T));
    }

    inline void deallocate(T* ptr, size_t length)
    {
        // DRIVER_DEBUG("deallocate<%s>(%zu)", typeid (T).name(), length);

        tmc_mspace_free(ptr);
    }

    template <typename U, typename ... Args>
    void construct(U* p, Args&&... args)
    {
        new (p) U(forward<Args>(args) ...);
    }

    template <typename U>
    void destroy(U* p)
    {
        p->~U();
    }

    friend inline bool operator==(
        const tile_allocator_t<T>& a, const tile_allocator_t<T>& b
    )
    {
        return *(a.mspace) == *(b.mspace);
    }

    friend inline bool operator!=(
        const tile_allocator_t<T>& a, const tile_allocator_t<T>& b
    )
    {
        return !(a == b);
    }

private:

    inline void _init_mspace(tmc_alloc_t *alloc)
    {
        mspace = shared_ptr<tmc_mspace>(new tmc_mspace, _free_mspace);
        *mspace = tmc_mspace_create_special(0, 0, alloc);
    }

    static void _free_mspace(tmc_mspace *mspace)
    {
        DRIVER_DEBUG("Freeing mpace starting at %zu", (size_t) *mspace);
        tmc_mspace_destroy(*mspace);
        delete mspace;
    }
};

} } /* namespace tcp_mpipe::driver */

#endif /* __TCP_MPIPE_DRIVER_ALLOCATOR_HPP__ */
