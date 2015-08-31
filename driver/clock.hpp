//
// Provides a way to compute time intervals between two events. The interface
// does not provide a way to know the date/hour/minute of an event, but can be
// used to how much time past between two events.
//
// Relies on the CPU cycle count instead of the system clock for efficiency.
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

#ifndef __RUSTY_DRIVER_CLOCK_HPP__
#define __RUSTY_DRIVER_CLOCK_HPP__

#include <cassert>
#include <cmath>            // round()
#include <cstdint>

#include <arch/cycle.h>     // get_cycle_count()

#include "driver/cpu.hpp"   // CYCLES_PER_SECOND, cycles_t

using namespace std;

using namespace rusty::driver::cpu;

namespace rusty {
namespace driver {

struct cpu_clock_t {
    // Interval between two dates.
    struct interval_t {
        cycles_t    cycles;

        inline interval_t(void) : cycles(0)
        {
        }

        // Creates a time interval from a number of microseconds (10^-6).
        inline interval_t(uint64_t microsec)
            : cycles(CYCLES_PER_SECOND / 1000000 * microsec)
        {
        }

        // Returns the number of microseconds (10^-6) in the time interval.
        inline uint64_t microsec(void)
        {
            return this->cycles * 1000000 / CYCLES_PER_SECOND;
        }

        inline interval_t operator+(interval_t other) const
        {
            return (interval_t) { this->cycles + other.cycles };
        }

        // If 'this' is < than 'other', is the same as 'other - this'.
        inline interval_t operator-(interval_t other) const
        {
            return (interval_t) { this->cycles - other.cycles };
        }

        inline interval_t operator*(double factor) const
        {
            return (interval_t) { (cycles_t) round(this->cycles * factor) };
        }

        inline interval_t operator*=(double factor)
        {
            this->cycles = (cycles_t) round(this->cycles * factor);
            return *this;
        }

        inline bool operator<(interval_t other) const
        {
            return this->cycles < other.cycles;
        }
    };

    // A time on which an interval can be computed.
    //
    // Time is stored as a CPU cycle count.
    struct time_t {
        cycles_t    cycles;

        // Returns the next time value in the domain (i.e. the next cycle count
        // value).
        inline time_t next(void) const
        {
            return (time_t) { this->cycles + 1 };
        }

        // Returns the interval between two times.
        inline interval_t operator-(time_t other) const
        {
            assert(this->cycles >= other.cycles);
            return (interval_t) { this->cycles - other.cycles };
        }

        inline time_t operator+(interval_t interval) const
        {
            return (time_t) { this->cycles + interval.cycles };
        }

        // Returns a 'time_t' object representing the current time.
        inline static time_t now(void)
        {
            return (time_t) { get_cycle_count() };
        }
    };
};

} } /* namespace rusty::driver */

namespace std {

// 'std::less<>' instance required for 'time_t' to be used in ordered
// containers.

using namespace rusty::driver;

template <>
struct less<cpu_clock_t::time_t> {
    inline bool operator()(cpu_clock_t::time_t a, cpu_clock_t::time_t b) const
    {
        return a.cycles < b.cycles;
    }
};

}

#endif /* __RUSTY_DRIVER_CLOCK_HPP__ */
