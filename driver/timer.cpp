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
#include <utility>              // move()

#include <arch/cycle.h>         // get_cycle_count()

#include "driver/cpu.hpp"       // cycles_t, CYCLES_PER_SECOND
#include "driver/driver.hpp"    // DRIVER_DEBUG()
#include "util/macros.hpp"      // UNLIKELY()

#include "driver/timer.hpp"

using namespace tcp_mpipe::driver::cpu;

namespace tcp_mpipe {
namespace driver {
namespace timer {

void timer_manager_t::tick(void)
{
    timer_manager_t::timers_t::const_iterator it;

    while ((it = timers.begin()) != timers.end()) {
        // Removes the timer before calling it as some callbacks could make
        // calls to 'schedule()' or 'remove()' and change the 'timers' member
        // field.
        // Similarly, the loop call 'timers.begin()' at each iteration as the
        // iterator could be invalidated.

        cycles_t current_count = get_cycle_count();
        if (it->first > current_count)
            break;

        DRIVER_DEBUG("Executes timer %" PRIu64, it->first);

        function<void(void)> f = move(it->second);
        timers.erase(it);

        f(); // Could invalidate 'it'.
    }
}

timer_manager_t::timer_id_t timer_manager_t::schedule(
    timer_manager_t::delay_t delay, const function<void()>& f
)
{
    cycles_t expire = get_cycle_count() + CYCLES_PER_SECOND * delay / 1000000;

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

} } } /* namespace tcp_mpipe::driver::timer */
