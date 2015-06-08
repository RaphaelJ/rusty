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
#include <functional>
#include <map>
#include <unordered_map>

using namespace std;

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
struct timer_manager_t {
    //
    // Member types
    //

    // CPU cycle counter value.
    typedef uint64_t                        cycles_t;

    // Timer delay in microseconds (10^-6).
    typedef uint64_t                        delay_t;

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
    typedef map<cycles_t, function<void()>> timers_t;

    // The 'destroy()' method uses the timer expiration date to retrieve and
    // remove a timer.
    typedef cycles_t                        timer_id_t;

    //
    // Static fields
    //

    // CPU Frequency in Hz.
    static constexpr cycles_t CYCLES_PER_SECOND = 1200000000;

    //
    // Fields
    //

    timers_t    timers;

    //
    // Methods
    //

    // Executes expired timers. This method should be called periodically.
    void tick(void);

    // Registers a timer with a delay in microseconds (10^-6) and a function.
    //
    // The timer will only be executed once.
    timer_id_t schedule(delay_t delay, const function<void()>& f);

    // Unschedules a timer by the identifier that has been returned by the
    // 'schedule()' call.
    //
    // Returns 'true' if the timer has been removed, 'false' if it was not
    // found.
    bool remove(timer_id_t timer_id);
};

} } } /* namespace tcp_mpipe::driver::timer */

#endif /* __TCP_MPIPE_DRIVER_TIMER_HPP__ */
