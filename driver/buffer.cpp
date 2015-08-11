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

#include <arch/cycle.h>         // get_cycle_count()

#include <gxio/mpipe.h>         // MPIPE_EDMA_DESC_*

#include "driver/driver.hpp"

#include "driver/buffer.hpp"
#include "driver/allocator.hpp"

namespace rusty {
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

} } } /* namespace rusty::driver::buffer */
