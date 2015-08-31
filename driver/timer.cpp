//
// Provides a timer manager which uses the CPU's cycle counter to trigger
// timers.
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

#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <utility>              // move()

#include <arch/cycle.h>         // get_cycle_count()

#include "driver/cpu.hpp"       // cycles_t, CYCLES_PER_SECOND
#include "driver/driver.hpp"    // DRIVER_DEBUG()
#include "util/macros.hpp"      // UNLIKELY()

#include "driver/timer.hpp"

using namespace rusty::driver::cpu;

namespace rusty {
namespace driver {
namespace timer {

} } } /* namespace rusty::driver::timer */
