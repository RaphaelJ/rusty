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

#include "net/endian.hpp"   // net_t, to_host(), to_network()

#include "net/checksum.hpp"

namespace rusty {
namespace net {

const partial_sum_t partial_sum_t::ZERO = partial_sum_t();

const checksum_t    checksum_t::ZERO    = checksum_t();

#ifndef NDEBUG
    // Reference implementation of the ones's complement sum.
    //
    // Only used for debugging.
    static uint16_t _ones_complement_sum_naive(const void *data, size_t size);
#endif /* NDEBUG */

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

    assert(data != nullptr);

    uint64_t        sum         = 0;
    const uint32_t  *data32     = (const uint32_t *) ((intptr_t) data & ~0x3);
    size_t          remaining   = size;

    // Processes the first bytes not aligned on 32 bits.
    intptr_t unaligned_offset = (intptr_t) data & 0x3;
    if (unaligned_offset) {
        size_t   unaligned_bytes  = sizeof (uint32_t) - unaligned_offset;
        // Loads the entire first word but masks the bytes which are before the
        // buffer. This should be safe as memory pages should be word-aligned.

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF << (unaligned_offset * 8);
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF >> (unaligned_offset * 8);
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif

        if (unaligned_bytes > remaining) {
            // Masks the bytes that are after the buffer.
            size_t mask_right = unaligned_bytes - remaining;
            unaligned_bytes = remaining;

            #if __BYTE_ORDER == __LITTLE_ENDIAN
                word_mask &= 0xFFFFFFFF >> (mask_right * 8);
            #elif __BYTE_ORDER == __BIG_ENDIAN
                word_mask &= 0xFFFFFFFF << (mask_right * 8);
            #else
                #error "Please set __BYTE_ORDER in <bits/endian.h>"
            #endif
        }

        sum += data32[0] & word_mask;
        remaining -= unaligned_bytes;
        data32++;
    }

    // Sums 32 bits at a time.
    while (remaining >= sizeof (uint32_t)) {
        sum += *data32;
        remaining -= sizeof (uint32_t);
        data32++;
    }

    // Sums the last bytes which could not fully fit a 32 bits integer.
    if (remaining > 0) {
        // Loads the last entire word but masks the bytes that are after the
        // buffer. This should be safe as a memory page should never end on a
        // word boundary.

        size_t mask_right = sizeof (uint32_t) - remaining;

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF >> (mask_right * 8);
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint32_t word_mask = 0xFFFFFFFF << (mask_right * 8);
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif

        sum += data32[0] & word_mask;
    }

    // 16 bits ones' complement sums of the two sub-sums and the carry bits.
    do
        sum = (sum >> 16) + (sum & 0xFFFF);
    while (sum >> 16);

    // If data started on an odd address, we computed the wrong sum. We computed
    // [0, a] +' [b, c] +' ... instead of [a, b] +' [c, d] +' ...
    //
    // The correct sum can be obtained by swapping bytes.
    uint16_t ret;
    if ((intptr_t) data & 0x1)
        ret = _swap_bytes((uint16_t) sum);
    else
        ret = (uint16_t) sum;

    assert(ret == _ones_complement_sum_naive(data, size));

    return ret;
}

partial_sum_t precomputed_sums_t::sum(size_t begin, size_t end) const
{
    assert(begin <= end);
    assert(end <= this->size);

    // If the section starts at an odd index. Removes the odd byte.
    size_t begin_div2 = begin / 2,
           end_div2   = end   / 2;

    uint32_t sum = this->table[end_div2] - this->table[begin_div2];

    // Removes the non-included first byte of the first 16 bits word.
    if (begin & 0x1) {
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            sum -= ((const char *) this->data)[begin - 1] << 8;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            sum -= ((const char *) this->data)[begin - 1];
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif

        // Removes the carry bit before swapping bytes.
        sum = (sum >> 16) + (sum & 0xFFFF);

        sum = (uint32_t) _swap_bytes((uint16_t) sum);
    }

    // Adds the included last byte.
    if (end & 0x1) {
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            sum += ((const char *) this->data)[end - 1];
        #elif __BYTE_ORDER == __BIG_ENDIAN
            sum += ((const char *) this->data)[end - 1] << 8;
        #else
            #error "Please set __BYTE_ORDER in <bits/endian.h>"
        #endif
    }

    sum = (sum >> 16) + (sum & 0xFFFF);

    size_t size = end - begin;

    partial_sum_t ret = partial_sum_t((uint16_t) sum, size & 0x1);

    assert(ret == partial_sum_t((const char *) this->data + begin, size));

    return ret;
}

const uint16_t *
precomputed_sums_t::_precompute_table(const void *_data, size_t _size)
{
    size_t size_table = _size / 2 + 1;

    uint16_t *table = new uint16_t[size_table];

    // Sums two bytes at a time.
    const uint16_t *data16 = (const uint16_t *) _data;

    table[0] = 0;
    for (size_t i = 1; i < size_table; i++) {
        // Sums pair of bytes in a 32 bits integer, so the carry bit will not be
        // lost.
        uint32_t sum = (uint32_t) table[i - 1] + (uint32_t) data16[i - 1];

        // Reports the carrybit in the stored 16 bits sum.
        table[i] = (uint16_t) ((sum >> 16) + (sum & 0xFFFF));
    }

    assert(
           table[size_table - 1]
        == _ones_complement_sum_naive(_data, _size ^ 0x1)
    );

    return table;
}

#ifndef NDEBUG
    static uint16_t _ones_complement_sum_naive(const void *data, size_t size)
    {
        uint64_t        sum     = 0;

        // Sums two bytes at a time.
        const uint16_t  *data16 = (const uint16_t *) data;

        while (size > 1) {
            sum     += *data16;
            size    -= 2;
            data16++;
        }

        // Adds left-over byte, if any.
        if (size > 0) {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
                uint16_t mask = 0x00FF;
            #elif __BYTE_ORDER == __BIG_ENDIAN
                uint16_t mask = 0xFF00;
            #else
                #error "Please set __BYTE_ORDER in <bits/endian.h>"
            #endif

            sum += *data16 & mask;
        }

        // Folds 64-bit sum to 16 bits.
        while (sum >> 16)
            sum = (sum >> 16) + (sum & 0xFFFF);

        return (uint16_t) sum;
    }
#endif /* NDEBUG */

} } /* namespace rusty::net */
