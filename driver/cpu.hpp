//
// Provides functions to manage dataplane Tiles.
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

#ifndef __TCP_MPIPE_DRIVERS_CPU_HPP__
#define __TCP_MPIPE_DRIVERS_CPU_HPP__

namespace tcp_mpipe {
namespace driver {
namespace cpu {

// Binds the current task to the n-th available dataplane Tile (first CPU is 0).
//
// Fails if there is less than n + 1 dataplane Tiles.
void bind_to_dataplane(unsigned int n);

} } } /* namespace tcp_mpipe::drivers:cpu */

#endif /* __TCP_MPIPE_DRIVERS_CPU_HPP__ */
