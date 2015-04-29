//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides an higher level interface to mPIPE buffers.
//

#include <cstdint>

#include <gxio/mpipe.h> // MPIPE_EDMA_DESC_*

#include "util/macros.hpp"

#include "driver/buffer.hpp"

namespace tcp_mpipe {
namespace driver {
namespace buffer {

const cursor_t cursor_t::EMPTY = { nullptr, 0, nullptr, 0 };

void cursor_t::_init_with_bdesc(
    const gxio_mpipe_bdesc_t *bdesc, size_t total_size
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
        next         = (gxio_mpipe_bdesc_t *) va;
        next_size    = total_size - current_size;
        return;
    default:
        DIE("Invalid buffer descriptor");
    };
}

} } } /* namespace tcp_mpipe::driver::buffer */
