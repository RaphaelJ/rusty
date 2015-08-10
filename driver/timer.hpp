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

#ifndef __TCP_MPIPE_DRIVER_TIMER_HPP__
#define __TCP_MPIPE_DRIVER_TIMER_HPP__

#include <cstdint>
#include <functional>       // less
#include <memory>           // allocator
#include <map>
#include <unordered_map>

#include "driver/cpu.hpp"   // cycles_t

using namespace std;

using namespace tcp_mpipe::driver::cpu;

namespace tcp_mpipe {
namespace driver {
namespace timer {

// Manages timers using uses the CPU's cycle counter.
//
// The 'tick()' method should be called periodically to execute expired timers.
//
// The manager is *not* thread-safe. Users must avoid concurrent calls to
// 'tick()', 'schedule()' and 'remove()'. Calling 'schedule()' or 'remove()'
// within a timer should be safe.
template <typename alloc_t = allocator<char *>>
struct timer_manager_t {
    //
    // Member types
    //

    // Timer delay in microseconds (10^-6).
    typedef uint64_t                                    delay_t;

    // Timers are stored by the cycle counter value for which they will expire.
    //
    // Only one function/timer can be mapped to an expiration counter value. In
    // the very rare case where two timers map on the same counter value, the
    // second one will be inserted in the next free cycle counter slot (e.g. if
    // two timers are inserted at counter value 123456, the second one will be
    // inserted at 123457).
    //
    // This should be pretty safe because a CPU cycle is a very small time unit
    // and the execution of the first timer will take more than one cycle. This
    // simplifies the implementation and makes it more efficient than a vector
    // of timers which requires numerous dynamic memory allocations.
    typedef map<
                cycles_t, function<void()>, less<cycles_t>, alloc_t
            >                                           timers_t;

    // The 'destroy()' method uses the timer expiration date to retrieve and
    // remove a timer.
    typedef cycles_t                                    timer_id_t;

    //
    // Fields
    //

    timers_t    timers;

    //
    // Methods
    //

    timer_manager_t(alloc_t _alloc = alloc_t());

    // Executes expired timers. This method should be called periodically.
    void tick(void);

    // Registers a timer with a delay in microseconds (10^-6) and a function.
    //
    // The timer will only be executed once.
    timer_id_t schedule(delay_t delay, function<void()> f);

    // Reschedules the given timer with a new delay. Returns the new 'timer_id'.
    timer_id_t reschedule(timer_id_t timer_id, delay_t new_delay);

    // Unschedules a timer by the identifier that has been returned by the
    // 'schedule()' call.
    //
    // Returns 'true' if the timer has been removed, 'false' if it was not
    // found.
    bool remove(timer_id_t timer_id);

private:
    // Sames as 'schedule' but doesn't produce a log message.
    timer_id_t _insert(delay_t delay, function<void()> f);
};

template <typename alloc_t>
timer_manager_t<alloc_t>::timer_manager_t(alloc_t _alloc)
    : timers(less<cycles_t>(), _alloc)
{
}

template <typename alloc_t>
void timer_manager_t<alloc_t>::tick(void)
{
    typename timers_t::const_iterator it;

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

template <typename alloc_t>
typename timer_manager_t<alloc_t>::timer_id_t
timer_manager_t<alloc_t>::schedule(delay_t delay, function<void()> f)
{
    timer_id_t timer_id = this->_insert(delay, f);

    DRIVER_DEBUG(
        "Schedules timer %" PRIu64 " with a %" PRIu64 " µs delay", timer_id,
        delay
    );

    return timer_id;
}

template <typename alloc_t>
typename timer_manager_t<alloc_t>::timer_id_t
timer_manager_t<alloc_t>::reschedule(timer_id_t timer_id, delay_t new_delay)
{
    auto it = timers.find(timer_id);
    assert(it != timers.end());

    timer_id_t new_timer_id = _insert(new_delay, it->second);

    timers.erase(timer_id);

    DRIVER_DEBUG(
        "Reschedules timer %" PRIu64 " as %" PRIu64 " with a %" PRIu64
        " µs delay", timer_id, new_timer_id, new_delay
    );

    return new_timer_id;
}

template <typename alloc_t>
bool timer_manager_t<alloc_t>::remove(timer_id_t timer_id)
{
    DRIVER_DEBUG("Unschedules timer %" PRIu64, timer_id);

    return timers.erase(timer_id);
}

template <typename alloc_t>
typename timer_manager_t<alloc_t>::timer_id_t
timer_manager_t<alloc_t>::_insert(delay_t delay, function<void()> f)
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

    return expire;
}

} } } /* namespace tcp_mpipe::driver::timer */

#endif /* __TCP_MPIPE_DRIVER_TIMER_HPP__ */
