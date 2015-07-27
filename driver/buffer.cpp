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

#include <cstdint>
#include <memory>               // shared_ptr, make_shared

#include <gxio/mpipe.h>         // MPIPE_EDMA_DESC_*

#include "driver/driver.hpp"

#include "driver/buffer.hpp"

namespace tcp_mpipe {
namespace driver {
namespace buffer {

#ifdef MPIPE_CHAINED_BUFFERS
    const cursor_t cursor_t::EMPTY = {
        shared_ptr<_buffer_desc_t>(nullptr), nullptr, 0,
        shared_ptr<cursor_t>(nullptr), 0
    };
#else
    const cursor_t cursor_t::EMPTY = {
        shared_ptr<_buffer_desc_t>(nullptr), nullptr, 0
    };
#endif /* MPIPE_CHAINED_BUFFERS */

void cursor_t::_init_with_bdesc(
    gxio_mpipe_context_t *context, gxio_mpipe_bdesc_t *bdesc, size_t total_size,
    bool is_managed
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
    desc = make_shared<_buffer_desc_t>(context, *bdesc, is_managed);

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

} } } /* namespace tcp_mpipe::driver::buffer */
