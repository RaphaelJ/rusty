//
// Provides an higher level interface to mPIPE buffers.
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

#ifndef __RUSTY_DRIVERS_BUFFER_HPP__
#define __RUSTY_DRIVERS_BUFFER_HPP__

#include <algorithm>        // min()
#include <cassert>
#include <cstring>
#include <functional>
#include <memory>           // shared_ptr

#include <gxio/mpipe.h>     // gxio_mpipe_*

#include "util/macros.hpp"

using namespace std;

namespace rusty {
namespace driver {
namespace buffer {

// Used internally to manage an mPIPE buffer life cycle.
struct _buffer_desc_t;

// Structure which can be used as an iterator to read and write into an mPIPE
// (possibly chained) buffer.
//
// The internal state of the cursor is never modified. That is, when data is
// read or written, a new cursor is returned without the previous one being
// modified. This makes it easier to use (you can chain methods, e.g.
// 'cursor.read(&a).drop(10).read(&b);') and backtracking is just a matter of
// reusing an old cursor.
struct cursor_t {

    // A cursor state is represented by the current buffer descriptor, the next
    // byte to read/write in the current buffer, the remaining bytes in this
    // buffer and a reference to the cursor containing the next buffer descriptor.
    //
    // 'current_size' can only be equal to zero if there is no buffer after.
    // That is, if the end of the current buffer is reached ('current_size'
    // become zero), the cursor must load the next buffer descriptor ('current'
    // must point to the next buffer's first byte). This makes 'read_in_place()'
    // and 'write_in_place()' implementations easier.

    // State of the cursor at the end of the buffer chain.
    static const cursor_t           EMPTY;

    shared_ptr<_buffer_desc_t>      desc;

    char                            *current;       // Next byte to read/write.
    size_t                          current_size;

    #ifdef MPIPE_CHAINED_BUFFERS

        shared_ptr<cursor_t>            next;           // Following buffers.
        size_t                          next_size;      // Total size of
                                                        // following buffers.

    #endif /* MPIPE_CHAINED_BUFFERS */

    // Creates a buffer's cursor from an ingress packet descriptor.
    //
    // If 'managed' is true, buffer descriptors will be freed automatically by
    // calling 'gxio_mpipe_push_buffer_bdesc()'.
    //
    // Complexity: O(n) where 'n' is the number of buffer descriptors in the
    // chain.
    template <typename alloc_t = allocator<char *>>
    inline cursor_t(
        gxio_mpipe_context_t *context, gxio_mpipe_idesc_t *idesc, bool managed,
        alloc_t alloc = alloc_t()
    )
    {
        // gxio_mpipe_idesc_to_bdesc() seems to be broken on MDE v4.3.2.
        // gxio_mpipe_bdesc_t edesc      = gxio_mpipe_idesc_to_bdesc(idesc);
        gxio_mpipe_bdesc_t edesc;
        edesc.word = idesc->words[7];

        size_t total_size = gxio_mpipe_idesc_get_xfer_size(idesc);

        _init_with_bdesc(context, &edesc, total_size, managed, alloc);
    }

    // Creates a buffer's cursor from a (possibly chained) buffer descriptor.
    //
    // If 'managed' is true, buffer descriptors will be freed automatically by
    // calling 'gxio_mpipe_push_buffer_bdesc()'.
    //
    // Complexity: O(n) where 'n' is the number of buffer descriptors in the
    // chain.
    template <typename alloc_t = allocator<char *>>
    inline cursor_t(
        gxio_mpipe_context_t *context, gxio_mpipe_bdesc_t *bdesc,
        size_t total_size, bool managed, alloc_t alloc = alloc_t()
    )
    {
        _init_with_bdesc(context, bdesc, total_size, managed, alloc);
    }

    // Returns the total number of remaining bytes.
    //
    // Complexity: O(1).
    inline size_t size(void) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            return current_size + next_size;
        #else
            return current_size;
        #endif/* MPIPE_CHAINED_BUFFERS */
    }

    // True if there is nothing more to read.
    //
    // Complexity: O(1).
    inline bool empty(void) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            if (current_size == 0) {
                assert(next_size == 0);
                return true;
            } else
                return false;
        #else
            return current_size == 0;
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Returns a new cursor which references the 'n' first bytes of the cursor.
    //
    // If 'n' is larger than the size of the cursor (given 'size()'), the
    // original cursor is returned.
    //
    // Complexity: O(1).
    inline cursor_t take(size_t n) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            if (n <= current_size)
                return cursor_t(desc, current, n, nullptr, 0);
            else if (n >= size())
                return *this;
            else {
                return cursor_t(
                    desc, current, current_size, next, next_size - n
                );
            }
        #else
            return cursor_t(desc, current, min(current_size, n));
        #endif/* MPIPE_CHAINED_BUFFERS */
    }

    // Returns a new cursor which references 'n' bytes after the cursor.
    //
    // Returns an empty cursor if the 'n' is larger than 'size()'.
    //
    // Complexity: O(n) with chained buffer, O(1) with unchained buffers.
    inline cursor_t drop(size_t n) const
    {
        if (n >= size())
            return EMPTY;
        else {
            #ifdef MPIPE_CHAINED_BUFFERS
                cursor_t cursor = *this;
                while (n > 0 && n >= cursor.current_size) {
                    n -= cursor.current_size;
                    cursor = *(cursor.next);
                }

                return cursor._drop_in_buffer(n);
            #else
                return _drop_in_buffer(n);
            #endif /* MPIPE_CHAINED_BUFFERS */
        }
    }

    // Equivalent to 'drop(sizeof (T))'.
    template <typename T>
    inline cursor_t drop() const
    {
        return drop(sizeof (T));
    }

    // Equivalent to 'drop(sizeof (T) * n)'.
    template <typename T>
    inline cursor_t drop(size_t n) const
    {
        return drop(sizeof (T) * n);
    }

    // -------------------------------------------------------------------------

    //
    // Copying read and write.
    //

    // Returns true if there is enough bytes left to read or write 'n' bytes*
    // using 'read()' or 'write()'.
    //
    // Complexity: O(1).
    inline bool can(size_t n) const
    {
        return n <= size();
    }

    // Equivalent to 'can(sizeof (T))'.
    template <typename T>
    inline bool can() const
    {
        return can(sizeof (T));
    }

    // Reads 'n' bytes of data. There must be enough bytes in the buffer to read
    // the item (see 'can()').
    //
    // Returns a new buffer which references the data following what has been
    // read.
    //
    // Complexity: O(n) where 'n' is the number of bytes to read.
    inline cursor_t read(char *data, size_t n) const
    {
        assert(can(n));

        #ifdef MPIPE_CHAINED_BUFFERS
            cursor_t cursor = *this;

            while (n > cursor.current_size) {
                memcpy(data, cursor.current, cursor.current_size);
                n -= cursor.current_size;
                cursor = *(cursor.next);
            }

            if (n > 0) {
                memcpy(data, cursor.current, n);
                cursor = cursor._drop_in_buffer(n);
            }

            return cursor;
        #else
            memcpy(data, current, n);
            return _drop_in_buffer(n);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Equivalent to 'read(data, sizeof (T))'.
    template <typename T>
    inline cursor_t read(T *data) const
    {
        return read((char *) data, sizeof (T));
    }

    // Writes 'n' bytes of data. There must be enough bytes in the buffer to
    // write the item (see 'can()').
    //
    // Returns a new buffer which references the data following what has been
    // written.
    //
    // Complexity: O(n) where 'n' is the number of bytes to write.
    inline cursor_t write(const char *data, size_t n) const
    {
        assert(can(n));

        #ifdef MPIPE_CHAINED_BUFFERS
            cursor_t cursor = *this;

            while (n > cursor.current_size) {
                memcpy(cursor.current, data, cursor.current_size);
                n -= cursor.current_size;
                cursor = *(cursor.next);
            }

            if (n > 0) {
                memcpy(cursor.current, data, n);
                cursor = cursor._drop_in_buffer(n);
            }

            return cursor;
        #else
            memcpy(current, data, n);
            return _drop_in_buffer(n);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Equivalent to 'write(data, sizeof (T))'.
    template <typename T>
    inline cursor_t write(const T *data) const
    {
        return write((const char *) data, sizeof (T));
    }

    // -------------------------------------------------------------------------

    //
    // In-place read and write.
    //

    // Returns true if there is enough bytes left in the *current buffer* to
    // read or write 'n' bytes with 'in_place()'.
    //
    // Complexity: O(1).
    inline bool can_in_place(size_t n) const
    {
        return n <= current_size;
    }

    // Equivalent to 'can_in_place(sizeof (T))'.
    template <typename T>
    inline bool can_in_place() const
    {
        return can_in_place(sizeof (T));
    }

    // Gives a pointer to read or write the given number of bytes directly in
    // the buffer's memory without copying.
    //
    // Returns a new buffer which references the data following what is to be
    // read or written.
    //
    // Complexity: O(1).
    inline cursor_t in_place(char **data, size_t n)
    {
        assert(can_in_place(n));

        *data = current;

        #ifdef MPIPE_CHAINED_BUFFERS
            if (n == current_size)
                return *next;
            else
                return _drop_in_buffer(n);
        #else
            return _drop_in_buffer(n);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Gives a pointer to read or write the given number of bytes directly in
    // the buffer's memory without copying.
    //
    // Returns a new buffer which references the data following what is to be
    // read or written.
    //
    // Complexity: O(1).
    inline cursor_t in_place(const char **data, size_t n) const
    {
        assert(can_in_place(n));

        *data = current;

        #ifdef MPIPE_CHAINED_BUFFERS
            if (n == current_size)
                return *next;
            else
                return _drop_in_buffer(n);
        #else
            return _drop_in_buffer(n);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Equivalent to 'in_place(data, sizeof (T))'.
    template <typename T>
    inline cursor_t in_place(T **data)
    {
        return in_place((char **) data, sizeof (T));
    }

    // Equivalent to 'in_place(data, sizeof (T))'.
    template <typename T>
    inline cursor_t in_place(const T **data) const
    {
        return in_place((const char **) data, sizeof (T));
    }

    // Gives to the given function a pointer to read 'n' bytes of data and a
    // cursor to the following data. The return value of the given function will
    // be forwarded as the return value of 'read_with()'.
    //
    // Will directly reference the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // The call to the given function is a tail-call.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to read.
    template <typename R>
    inline R read_with(function<R(const char *, cursor_t)> f, size_t n) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            if (can_in_place(n)) {
                const char *p;
                cursor_t cursor = in_place(&p, n);
                return f(p, cursor);
            } else {
                assert(can(n));
                char data[n];
                cursor_t cursor = read(data, n);
                return f(data, cursor);
            }
        #else
            const char *p;
            cursor_t cursor = in_place(&p, n);
            return f(p, cursor);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Equivalent to 'read_with<R>(f, sizeof (T))'.
    template <typename T, typename R>
    inline R read_with(function<R(const T *, cursor_t)> f) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
             if (can_in_place<T>()) {
                const T *p;
                cursor_t cursor = in_place<T>(&p);
                return f(p, cursor);
            } else {
                assert(can<T>());
                T data;
                cursor_t cursor = read<T>(&data);
                return f(&data, cursor);
            }
        #else
            const T *p;
            cursor_t cursor = in_place<T>(&p);
            return f(p, cursor);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Gives a pointer to read 'n' bytes of data to the function.
    //
    // Will directly reference the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // The call to the given function is *not* a tail-call.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to read.
    inline cursor_t read_with(function<void(const char *)> f, size_t n) const
    {
        return read_with<cursor_t>([&f](const char *data, cursor_t cursor) {
            f(data);
            return cursor;
        }, n);
    }

    // Equivalent to 'read_with(f, sizeof (T))'.
    template <typename T>
    inline cursor_t read_with(function<void(const T *)> f) const
    {
        return read_with<T, cursor_t>([&f](const T *data, cursor_t cursor) {
            f(data);
            return cursor;
        });
    }

    // Gives a pointer to write 'n' bytes of data to the function.
    //
    // Will directly reference the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // State of the memory referenced by the pointer is undefined.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to write.
    inline cursor_t write_with(function<void(char *)> f, size_t n)
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            if (can_in_place(n)) {
                char *p;
                cursor_t cursor = in_place(&p, n);
                f(p);
                return cursor;
            } else {
                assert(can(n));
                char data[n];
                f(data);
                return write(data, n);
            }
        #else
            char *p;
            cursor_t cursor = in_place(&p, n);
            f(p);
            return cursor;
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Equivalent to 'write_with(f, sizeof (T))'.
    template <typename T>
    inline cursor_t write_with(function<void(T *)> f)
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            if (can_in_place<T>()) {
                T *p;
                cursor_t cursor = in_place<T>(&p);
                f(p);
                return cursor;
            } else {
                assert(can<T>());
                T data;
                f(&data);
                return write<T>(&data);
            }
        #else
            T *p;
            cursor_t cursor = in_place<T>(&p);
            f(p);
            return cursor;
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

    // Executes the given function on each buffer, in order.
    //
    // Complexity: O(n).
    inline void for_each(function<void(const char *, size_t)> f) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            cursor_t cursor = *this;

            while (!cursor.empty()) {
                f(cursor.current, cursor.current_size);
                cursor = *cursor._next;
            }
        #else
            if (!empty())
                f(current, current_size);
        #endif /* MPIPE_CHAINED_BUFFERS */
    }

private:
    #ifdef MPIPE_CHAINED_BUFFERS
        cursor_t(
            shared_ptr<_buffer_desc_t> _desc, char *_current,
            size_t _current_size,
            shared_ptr<cur> _next, size_t _next_size
        ) : desc(_desc), current(_current), current_size(_current_size),
            next(_next), next_size(_next_size)
    #else
        cursor_t(
            shared_ptr<_buffer_desc_t> _desc, char *_current,
            size_t _current_size
        ) : desc(_desc), current(_current), current_size(_current_size)
    #endif /* MPIPE_CHAINED_BUFFERS */
    {
    }

    // Complexity: O(n) where 'n' is the number of buffer descriptors in the
    // chain.
    //
    // The allocator is used to allocate the 'shared_ptr'.
    template <typename alloc_t = allocator<char *>>
    void _init_with_bdesc(
        gxio_mpipe_context_t *context, gxio_mpipe_bdesc_t *bdesc,
        size_t total_size, bool managed, alloc_t alloc = alloc_t()
    );

    // Returns a new cursor which references 'n' bytes after the cursor.
    //
    // Does *not* handle the case when 'n' is exactly equal to 'current_size'
    // (i.e. when a new buffer must be loaded).
    //
    // Complexity: O(1).
    inline cursor_t _drop_in_buffer(size_t n) const
    {
        #ifdef MPIPE_CHAINED_BUFFERS
            assert(can_in_place(n) && (n < current_size || next == nullptr));

            return {
                desc, current + n, current_size - n,
                next, next_size
            };
        #else
            assert(can_in_place(n));

            return { desc, current + n, current_size - n };
        #endif
    }
};

struct _buffer_desc_t {
    gxio_mpipe_context_t    *context;
    gxio_mpipe_bdesc_t      bdesc;
    bool                    is_managed; // If true, the buffer will be released
                                        // when this object will be destructed.

    _buffer_desc_t(
        gxio_mpipe_context_t *_context, gxio_mpipe_bdesc_t _bdesc,
        bool _is_managed
    ) : context(_context), bdesc(_bdesc), is_managed(_is_managed)
    {
    }

    ~_buffer_desc_t(void)
    {
        if (is_managed)
            gxio_mpipe_push_buffer_bdesc(context, bdesc);
    }
};

template <typename alloc_t>
void cursor_t::_init_with_bdesc(
    gxio_mpipe_context_t *context, gxio_mpipe_bdesc_t *bdesc, size_t total_size,
    bool is_managed, alloc_t alloc
)
{
    // The end of the buffer chain could be reached because:
    // 1) there is no buffer descriptor.
    // 2) there is another buffer descriptor but we limited the number of bytes
    //    we can use (this is used by slice methods such as 'take()').
    // 3) the descriptor is invalid (last buffer in a chain).

    if (
           bdesc == nullptr || total_size == 0
        || bdesc->c == MPIPE_EDMA_DESC_WORD1__C_VAL_INVALID
    ) {
        assert(total_size == 0);
        *this = EMPTY;
        return;
    }

    // Allocates a manageable buffer descriptor.
    // desc = make_shared<_buffer_desc_t>(context, *bdesc, is_managed);
    desc = allocate_shared<_buffer_desc_t>(alloc, context, *bdesc, is_managed);

    // The last 42 bits of the buffer descriptor contain the virtual address of
    // the buffer with the lower 7 bits being the offset of packet data inside
    // this buffer.
    //
    // When the buffer is chained with other buffers, the next buffer descriptor
    // is written in the first 8 bytes of the buffer and the offset is at least
    // 8 bytes.

    char    *va    = (char *) ((intptr_t) bdesc->va << 7);
    size_t  offset = bdesc->__reserved_0;

    current = va + offset;

    #ifdef MPIPE_CHAINED_BUFFERS
        size_t buffer_size = gxio_mpipe_buffer_size_enum_to_buffer_size(
            (gxio_mpipe_buffer_size_enum_t) bdesc->size
        );

        switch (bdesc->c) {
        case MPIPE_EDMA_DESC_WORD1__C_VAL_UNCHAINED:
            assert(total_size <= buffer_size - offset);

            current_size = total_size;
            next         = nullptr;
            next_size    = 0;
            return;
        case MPIPE_EDMA_DESC_WORD1__C_VAL_CHAINED:
            current_size = min(total_size, buffer_size - offset);
            next_size    = total_size - current_size;
            next         = make_shared<cursor_t>(
                context, (gxio_mpipe_bdesc_t *) va, next_size, is_managed
            );
            return;
        default:
            DRIVER_DIE("Invalid buffer descriptor");
        };
    #else
        assert(bdesc->c == MPIPE_EDMA_DESC_WORD1__C_VAL_UNCHAINED);

        current_size = total_size;
    #endif /* MPIPE_CHAINED_BUFFERS */
}

} } } /* namespace rusty::driver:buffer */

#endif /* __RUSTY_DRIVERS_BUFFER_HPP__ */
