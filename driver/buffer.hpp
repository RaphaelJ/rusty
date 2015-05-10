//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides an higher level interface to mPIPE buffers.
//

#ifndef __TCP_MPIPE_DRIVERS_BUFFER_HPP__
#define __TCP_MPIPE_DRIVERS_BUFFER_HPP__

#include <cassert>
#include <cstring>
#include <functional>

#include <gxio/mpipe.h> // gxio_mpipe_*

#include "util/macros.hpp"

using namespace std;

namespace tcp_mpipe {
namespace driver {
namespace buffer {

// Structure which can be used as an iterator to read and write into an mPIPE
// (possibly chained) buffer.
//
// The internal state of the cursor is never modified. That is, when data is
// read or written, a new cursor is returned without the previous one being
// modified. This makes it easier to use (you can chain methods, e.g.
// 'cursor.read(&a).drop(10).read(&b);') and backtracking is just a matter of
// reusing an old cursor.
struct cursor_t {

    // A cursor state is represented by the next byte to read/write in the
    // current buffer, the remaining bytes in this buffer and a reference to the
    // next buffer descriptor.
    //
    // 'current_size' can only be equal to zero if there is no buffer after.
    // That is, if the end of the current buffer is reached ('current_size'
    // become zero), the cursor must load the next buffer descriptor. This makes
    // 'read_in_place()' and 'write_in_place()' implementations easier.

    // State of the cursor at the end of the buffer chain.
    static const cursor_t EMPTY;

    char                *current;       // Next byte to read/write.
    size_t              current_size;

    gxio_mpipe_bdesc_t  *next;
    size_t              next_size;      // Remaining data in following buffers.

    // Complexity: O(1).
    cursor_t(gxio_mpipe_idesc_t *idesc)
    {
        // gxio_mpipe_idesc_to_bdesc() seems to be broken on MDE v4.3.2.
        // gxio_mpipe_bdesc_t edesc      = gxio_mpipe_idesc_to_bdesc(idesc);
        gxio_mpipe_bdesc_t edesc;
        edesc.word = idesc->words[7];

        size_t total_size = gxio_mpipe_idesc_get_xfer_size(idesc);

        _init_with_bdesc(&edesc, total_size);
    }

    // Complexity: O(1).
    cursor_t(gxio_mpipe_bdesc_t *bdesc, size_t total_size)
    {
        _init_with_bdesc(bdesc, total_size);
    }

    // Returns the total number of remaining bytes.
    //
    // Complexity: O(1).
    inline size_t size() const
    {
        return current_size + next_size;
    }

    // True if there is nothing more to read.
    //
    // Complexity: O(1).
    inline bool is_empty(cursor_t cursor) const
    {
        if (current_size == 0) {
            assert(next_size == 0);
            return true;
        } else
            return false;
    }

    // Returns a new cursor which references the 'n' first bytes of the cursor.
    //
    // Complexity: O(1).
    inline cursor_t take(size_t n) const
    {
        if (n <= current_size)
            return cursor_t(current, n, nullptr, 0 );
        else
            return cursor_t(current, current_size, next, next_size - n);
    }

    // Returns a new cursor which references 'n' bytes after the cursor.
    // Returns an empty cursor if the 'n' is larger than 'size()'.
    //
    // Complexity: O(n).
    inline cursor_t drop(size_t n) const
    {
        if (n >= size())
            return EMPTY;
        else {
            cursor_t cursor = *this;
            while (n >= cursor.current_size) {
                n -= cursor.current_size;
                cursor = cursor._next_buffer();
            }

            return {
                cursor.current + n, cursor.current_size - n,
                cursor.next, cursor.next_size
            };
        }
    }

    // Equivalent to drop(sizeof (T)).
    //
    // Complexity: O(n).
    template <typename T>
    inline cursor_t drop() const
    {
        return drop(sizeof (T));
    }

    // Equivalent to drop(sizeof (T) * n).
    //
    // Complexity: O(n).
    template <typename T>
    inline cursor_t drop(size_t n) const
    {
        return drop(sizeof (T) * n);
    }

    // Returns true if there is enough bytes left to read or write one instance
    // of the requested item using 'read()' or 'write()'.
    //
    // Complexity: O(1).
    template <typename T>
    inline bool can() const
    {
        return sizeof (T) <= size();
    }

    // Reads one instance of the given type. There must be enough bytes in the
    // buffer to read the item (see 'can()').
    //
    // Returns a new buffer which references the data following what has been
    // read.
    //
    // Complexity: O(n) where 'n' is the number of bytes to read.
    template <typename T>
    inline cursor_t read(T *data) const
    {
        assert(can<T>());

        char        *data_char  = (char *) data;
        cursor_t    cursor      = *this;
        size_t      to_read     = sizeof (T);

        while (to_read >= cursor.current_size) {
            memcpy(data_char, cursor.current, cursor.current_size);
            cursor = cursor._next_buffer();
            to_read -= cursor.current_size;
        }

        if (to_read > 0) {
            memcpy(data_char, cursor.current, to_read);
            cursor = cursor_t( // == cursor.drop(to_read)
                cursor.current + to_read, cursor.current_size - sizeof (T),
                cursor.next, cursor.next_size
            );
        }

        return cursor;
    }

    // Writes one instance of the given type. There must be enough bytes in the
    // buffer to write the item (see 'can()').
    //
    // Returns a new buffer which references the data following what has been
    // written.
    //
    // Complexity: O(n) where 'n' is the number of bytes to read.
    template <typename T>
    inline cursor_t write(const T *data) const
    {
        assert(can<T>());

        const char  *data_char = (const char *) data;
        cursor_t    cursor     = *this;
        size_t      to_write   = sizeof (T);

        while (to_write >= cursor.current_size) {
            memcpy(cursor.current, data_char, cursor.current_size);
            cursor = cursor._next_buffer();
            to_write -= cursor.current_size;
        }

        if (to_write > 0) {
            memcpy(cursor.current, data_char, to_write);
            cursor = cursor_t( // == cursor.drop(to_write)
                cursor.current + to_write, cursor.current_size - sizeof (T),
                cursor.next, cursor.next_size
            );
        }

        return cursor;
    }

    // Returns true if there is enough bytes left in the *current buffer* to
    // read or write one instance of the requested item using 'in_place()'.
    //
    // Complexity: O(1).
    template <typename T>
    inline bool can_in_place() const
    {
        return sizeof (T) <= current_size;
    }

    // Gives a pointer to read or write the given data directly in the buffer's
    // memory without copying.
    //
    // Returns a new buffer which references the data following what is to be
    // read or written.
    //
    // Complexity: O(1).
    template <typename T>
    inline cursor_t in_place(T **data)
    {
        assert(can_in_place<T>());

        *data = (T *) current;

        return cursor_t( // == this->drop(sizeof (T))
            this->current + sizeof (T), this->current_size - sizeof (T),
            this->next,                 this->next_size
        );
    }

    // Gives to the given function a pointer to read one instance of the data
    // and a cursor to the following data. The return value of the given
    // function will be forwarded as the return value of 'read_with()'.
    //
    // Will directly refer ence the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // The call to the given function is a tail-call.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to read.
    template <typename T, typename R>
    inline R read_with(function<R(const T *, cursor_t)> f)
    {
        if (can_in_place<T>()) {
            T *p;
            cursor_t cursor = in_place<T>(&p);
            return f(p, cursor);
        } else {
            T data;
            cursor_t cursor = read<T>(&data);
            return f(&data, cursor);
        }
    }

    // Gives a pointer to read one instance of the data to the function.
    //
    // Will directly reference the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // The call to the given function is *not* a tail-call.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to read.
    template <typename T>
    inline cursor_t read_with(function<void(const T *)> f)
    {
        return read_with<T, cursor_t>([&f](const T *data, cursor_t cursor) {
            f(data);
            return cursor;
        });
    }

    // Gives a pointer to write one instance of the data to the function.
    //
    // Will directly reference the buffer's memory if it's possible
    // ('can_in_place()'), will gives a reference to a copy otherwise.
    //
    // State of the memory referenced by the pointer is undefined.
    //
    // Complexity: O(1) (best-case) or O(n) (worst-case) where 'n' is the number
    // of bytes to write.
    template <typename T>
    inline cursor_t write_with(function<void(T *)> f)
    {
        if (can_in_place<T>()) {
            T *p;
            cursor_t cursor = in_place<T>(&p);
            f(p);
            return cursor;
        } else {
            T data;
            f(&data);
            return write<T>(&data);
        }
    }

private:
    cursor_t(
        char *_current,   size_t _current_size,
        gxio_mpipe_bdesc_t *_next, size_t _next_size
    ) : current(_current), current_size(_current_size),
        next(_next), next_size(_next_size)
    {
    }

    // Complexity: O(1).
    void _init_with_bdesc(const gxio_mpipe_bdesc_t *bdesc, size_t total_size);

    // Skips to the next buffer descriptor.
    //
    // Complexity: O(1).
    inline cursor_t _next_buffer(void) const
    {
        return cursor_t(next, next_size);
    }
};

} } } /* namespace tcp_mpipe::driver:buffer */

#endif /* __TCP_MPIPE_DRIVERS_BUFFER_HPP__ */
