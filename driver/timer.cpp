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

#include <cinttypes>
#include <cstdint>
#include <map>
#include <unordered_map>

#include <arch/cycle.h>         // get_cycle_count()

#include "driver/driver.hpp"    // DRIVER_DEBUG()
#include "util/macros.hpp"      // UNLIKELY()

#include "driver/timer.hpp"

namespace tcp_mpipe {
namespace driver {

void timer_manager_t::tick(void)
{
    // Iterates expired timers, executes them and removes them.

    auto it = timers.begin();
    while (it != timers.end()) {
        cycles_t current_count = get_cycle_count();

        if (it->first > current_count)
            break;

        DRIVER_DEBUG("Executes timer %" PRIu64, it->first);
        it->second();

        it = timers.erase(it); // TODO: removes a batch of timers in one call
                               // for performances.
    }
}

timer_manager_t::timer_id_t
timer_manager_t::schedule(uint64_t delay, const function<void()>& f)
{
    timer_manager_t::cycles_t expire =
        get_cycle_count() + CYCLES_PER_SECOND * delay / 1000000;

    insert:
    {
        auto inserted = timers.emplace(expire, f);

        if (UNLIKELY(!inserted.second)) {
            expire++;
            goto insert;
        }
    }

    DRIVER_DEBUG(
        "Schedules timer %" PRIu64 " with %" PRIu64 " µs delay", expire, delay
    );

    return expire;
}

bool timer_manager_t::remove(timer_manager_t::timer_id_t timer_id)
{
    DRIVER_DEBUG("Unschedules timer %" PRIu64, timer_id);

    return timers.erase(timer_id);
}

} } /* namespace tcp_mpipe::driver */
