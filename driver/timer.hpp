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

#ifndef __RUSTY_DRIVER_TIMER_HPP__
#define __RUSTY_DRIVER_TIMER_HPP__

#include <cassert>
#include <cstdint>
#include <cinttypes>        // PRIu64
#include <functional>       // less
#include <memory>           // allocator
#include <map>
#include <unordered_map>

#include "driver/clock.hpp" // cpu_clock_t

using namespace std;

namespace rusty {
namespace driver {

// Manages timers using uses the CPU's cycle counter.
//
// The 'tick()' method should be called periodically to execute expired timers.
//
// The manager is *not* thread-safe. Users must avoid concurrent calls to
// 'tick()', 'schedule()' and 'remove()'. Calling 'schedule()' or 'remove()'
// within a timer should be safe.
template <typename alloc_t = allocator<char *>>
struct cpu_timer_manager_t {
    //
    // Member types
    //

    // Timers are stored by the time they will expire.
    //
    // Only one function/timer can be mapped to an expiration date. In
    // the very rare case where two timers map on the same expiration date, the
    // second one will be inserted in the next free expiration date in the
    // domain.
    //
    // As expiration dates are based on the CPU cycle counter, the next
    // expiration date is only once cycle later. This should be pretty safe to
    // use the next CPU cycle because a CPU cycle is a very small time unit and
    // the execution of the first timer will take more than one cycle. This
    // simplifies the implementation and makes it more efficient than a vector
    // of timers which requires numerous dynamic memory allocations.
    typedef map<
                cpu_clock_t::time_t, function<void()>,
                less<cpu_clock_t::time_t>, alloc_t
            >                   timers_t;

    // The 'destroy()' method uses the timer expiration date to retrieve and
    // remove a timer.
    typedef cpu_clock_t::time_t timer_id_t;

    //
    // Fields
    //

    timers_t    timers;

    //
    // Methods
    //

    cpu_timer_manager_t(alloc_t _alloc = alloc_t());

    // Executes expired timers. This method should be called periodically.
    void tick(void);

    // Registers a timer. The timer will only be executed once.
    timer_id_t schedule(cpu_clock_t::interval_t delay, function<void()> f);

    // Reschedules the given timer with a new delay. Returns the new 'timer_id'.
    timer_id_t reschedule(
        timer_id_t timer_id, cpu_clock_t::interval_t new_delay
    );

    // Unschedules a timer by the identifier that has been returned by the
    // 'schedule()' call.
    //
    // Returns 'true' if the timer has been removed, 'false' if it was not
    // found.
    bool remove(timer_id_t timer_id);

private:
    // Sames as 'schedule' but doesn't produce a log message.
    timer_id_t _insert(cpu_clock_t::interval_t delay, function<void()> f);
};

template <typename alloc_t>
cpu_timer_manager_t<alloc_t>::cpu_timer_manager_t(alloc_t _alloc)
    : timers(less<cpu_clock_t::time_t>(), _alloc)
{
}

template <typename alloc_t>
void cpu_timer_manager_t<alloc_t>::tick(void)
{
    typename timers_t::const_iterator it;

    while ((it = timers.begin()) != timers.end()) {
        // Removes the timer before calling it as some callbacks could make
        // calls to 'schedule()' or 'remove()' and change the 'timers' member
        // field.
        // Similarly, the loop call 'timers.begin()' at each iteration as the
        // iterator could be invalidated.

        cpu_clock_t::time_t now = cpu_clock_t::time_t::now();
        if (less<cpu_clock_t::time_t>()(now, it->first))
            break;

        DRIVER_DEBUG("Executes timer %" PRIu64, it->first.cycles);

        function<void(void)> f = move(it->second);
        timers.erase(it);

        f(); // Could invalidate 'it'.
    }
}

template <typename alloc_t>
typename cpu_timer_manager_t<alloc_t>::timer_id_t
cpu_timer_manager_t<alloc_t>::schedule(
    cpu_clock_t::interval_t delay, function<void()> f
)
{
    timer_id_t timer_id = this->_insert(delay, f);

    DRIVER_DEBUG(
        "Schedules timer %" PRIu64 " with a %" PRIu64 " µs delay",
        timer_id.cycles, delay.microsec()
    );

    return timer_id;
}

template <typename alloc_t>
typename cpu_timer_manager_t<alloc_t>::timer_id_t
cpu_timer_manager_t<alloc_t>::reschedule(
    timer_id_t timer_id, cpu_clock_t::interval_t new_delay
)
{
    auto it = timers.find(timer_id);
    assert(it != timers.end());

    timer_id_t new_timer_id = _insert(new_delay, it->second);

    timers.erase(timer_id);

    DRIVER_DEBUG(
        "Reschedules timer %" PRIu64 " as %" PRIu64 " with a %" PRIu64
        " µs delay", timer_id.cycles, new_timer_id.cycles, new_delay.microsec()
    );

    return new_timer_id;
}

template <typename alloc_t>
bool cpu_timer_manager_t<alloc_t>::remove(timer_id_t timer_id)
{
    DRIVER_DEBUG("Unschedules timer %" PRIu64, timer_id.cycles);

    return timers.erase(timer_id);
}

template <typename alloc_t>
typename cpu_timer_manager_t<alloc_t>::timer_id_t
cpu_timer_manager_t<alloc_t>::_insert(
    cpu_clock_t::interval_t delay, function<void()> f
)
{
    cpu_clock_t::time_t expire = cpu_clock_t::time_t::now() + delay;

    // Uses the next time slot if the current one already exist.
    while (!timers.emplace(expire, f).second)
        expire = expire.next();

    return expire;
}

} } /* namespace rusty::driver */

#endif /* __RUSTY_DRIVER_TIMER_HPP__ */
