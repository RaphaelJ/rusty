//
// Computes a checksum required by IPv4 and TCP protocols.
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
#include <cstdint>
#include <cstring>

#include <endian.h>         // __BIG_ENDIAN, __BYTE_ORDER, __LITTLE_ENDIAN

#include "net/endian.hpp"   // net_t

#include "net/checksum.hpp"

namespace tcp_mpipe {
namespace net {

const partial_sum_t partial_sum_t::ZERO = partial_sum_t();

const checksum_t    checksum_t::ZERO    = checksum_t();

uint16_t _ones_complement_sum(const void *data, size_t size)
{
    // The 16 bits ones' complement sum is the ones' complement addition of
    // every pair of bytes. If there is an odd number of bytes, then a zero byte
    // is virtually added to the buffer.
    //
    // e.g. the ones' complement sum of the bytes [a, b, c, d, e, f, g] is
    // [a, b] +' [c, d] +' [e, f] +' [g, 0] where +' is the ones' complement
    // addition.
    //
    // Ones' complement addition is standard addition but with the carry bit
    // added to the result.
    //
    // As an example, here is the 4 bits ones' complement addition of 1111 and
    // 1011:
    //
    //        1111
    //      + 1101
    //      ------
    //      1 1000
    //      \--------> The carry bit here must be added to the result (1000).
    //        1001 --> 4 bits ones' complement addition of 1111 and 1011.
    //
    // The 16 bits ones' complement sum is thus equal to:
    //
    //      uint16_t *p = (uint16_t *) data;
    //
    //      // Computes the ones' complement sum.
    //      uint32_t sum = 0;
    //      for (int i = 0; i < size / 2; i++) {
    //          sum += p[i];
    //
    //          if (sum >> 16) // if carry bit
    //              sum += 1;
    //      }
    //
    // Instead of only adding 16 bits at a time and checking for a carry bit
    // at each addition (which produces a lot unpredictable branches), we use a
    // trick from [1].
    //
    // The trick is to use a 64 bits integer as sum's accumulator and adds two
    // pair of bytes at a time (2 x 16 bits = 32 bits). The 32 mosts significant
    // bits of the 64 bits accumulator will accumulate carry bits while the 32
    // least significant bits will accumulate two 16 bits sums:
    //
    // +-----------------------------------+-----------------+-----------------+
    // |   32 bits carry bits accumulator  | 2nd 16 bits sum | 1st 16 bits sum |
    // +-----------------------------------+-----------------+-----------------+
    // \-----------------------------------------------------------------------/
    //                            64 bits accumulator
    //
    // It's not a problem that the least significant 16 bits sum produces a
    // carry bit as ones' complement addition is commutative and as this carry
    // bit will be added to the second sum, which will be summed with first one
    // later.
    //
    // The algorithm then adds the 32 bits carry bits accumulator to the sum of
    // the two 16 bits sums to get the final sum..
    //
    // [1]: http://tools.ietf.org/html/rfc1071

    assert (data != nullptr && size >= 0);

    uint64_t       sum      = 0;
    const uint32_t *data32  = (const uint32_t *) ((intptr_t) data & ~0x3);

    // Processes the first bytes not aligned on 32 bits.
    intptr_t unaligned_offset = (intptr_t) data & 0x3;
    if (unaligned_offset) {
        // Loads the entire first word but masks the bytes which are before the
        // buffer. This should be safe as memory pages should be word-aligned.

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF << (unaligned_offset * 8);
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF >> (unaligned_offset * 8);
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif

        sum += data32[0] & word_mask;
        size -= 4 - unaligned_offset;
        data32++;
    }

    // Sums 32 bits at a time.
    while (size > sizeof (uint32_t)) {
        sum += *data32;
        size -= sizeof (uint32_t);
        data32++;
    }

    // Sums the last bytes which could not fully fit a 32 bits integer.
    if (size > 0) {
        // Loads the last entire word but masks the bytes that are after the
        // buffer. This should be safe as a memory page should never end on a
        // word boundary.

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF >> ((4 - unaligned_offset) * 8);
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF << ((4 - unaligned_offset) * 8);
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif

        sum += data32[0] & word_mask;
    }

    // 16 bits ones' complement sums of the two sub-sums and the carry bits.
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // If data started on an odd address, we computed the wrong sum. We computed
    // [0, a] +' [b, c] +' ... instead of [a, b] +' [c, d] +' ...
    //
    // The correct sum can be obtained by swapping bytes.
    if ((intptr_t) data & 0x1)
        return _swap_bytes((uint16_t) sum);
    else
        return (uint16_t) sum;
}

} } /* namespace tcp_mpipe::net */
