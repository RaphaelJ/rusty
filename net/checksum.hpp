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

#ifndef __TCP_MPIPE_NET_CHECKSUM_HPP__
#define __TCP_MPIPE_NET_CHECKSUM_HPP__

#include <cstdint>

#include "net/endian.hpp"   // net_t

namespace tcp_mpipe {
namespace net {

// Computes the 16 bits ones' complement sum of the given buffer.
uint16_t _ones_complement_sum(const void *data, size_t size);

// Swaps the two bytes of the integer ([a, b] -> [b, a]).
static inline uint16_t _swap_bytes(uint16_t bytes);

// -----------------------------------------------------------------------------

// Partially computed checksums.
//
// Used to compute a checksum incrementally.
//
// Can be computed with 'partial_sum_t()' and combined with an other partially
// computed sum with 'append()'. The checksum can be then computed from this
// partially computed sum with 'checksum_t()'.
struct partial_sum_t {
    uint16_t    sum;

    // 'true' when the sum has been computed on an odd number of bytes.
    bool        odd;

    // Sum of an empty buffer.
    static const partial_sum_t ZERO;

    // Initializes the partial sum to zero (sum of an empty buffer).
    inline partial_sum_t(void)
    {
        this->sum = 0;
        this->odd = false;
    }

    // Initializes from an already computed sum.
    inline partial_sum_t(uint16_t _sum, bool _odd)
    {
        this->sum = _sum;
        this->odd = _odd;
    }

    // Computes the sum of a buffer.
    inline partial_sum_t(const void *data, size_t size)
    {
        this->sum = _ones_complement_sum(data, size);
        this->odd = (bool) (size & 0x1);
    }

    // Computes the sum of a buffer cursor.
    template <typename cursor_t>
    inline partial_sum_t(cursor_t cursor) : partial_sum_t()
    {
        cursor.for_each([this](const void *buffer, size_t size) {
            *this = this->append(partial_sum_t(buffer, size));
        });
    }

    // Returns the partial sum that would have been obtained if the buffer of the
    // current sum and the buffer of the given partial sum were attached.
    inline partial_sum_t append(partial_sum_t second) const
    {
        uint32_t sum = this->sum;

        // When the first sum was computed on an odd number of bytes, we
        // virtually added a zero byte to the buffer. We need to swap the bytes
        // of the second sum to cancel this padding.
        if (this->odd)
            sum += _swap_bytes(second.sum);
        else
            sum += second.sum;

        sum += sum >> 16; // Carry bit.

        return { (uint16_t) sum, this->odd != second.odd };
    }

    inline friend bool operator==(partial_sum_t a, partial_sum_t b)
    {
        return a.sum == b.sum && a.odd == b.odd;
    }

    inline friend bool operator!=(partial_sum_t a, partial_sum_t b)
    {
        return !(a == b);
    }
};

// -----------------------------------------------------------------------------

// Precomputed partial sum table.
//
// Once computed from a data buffer, the precomputed table can gives in constant
// time the one's complement sum of any subsection of the buffer.
struct precomputed_sums_t {
    const void      *data;
    const size_t    size;

    const uint16_t  *table;

    // Given a data buffer and its size, precomputes the one's complement sum
    // table.
    //
    // '_data' must never be de-allocated before the precomputed sum table.
    //
    // Complexity: O(_size).
    precomputed_sums_t(const void *_data, size_t _size)
        : data(_data), size(_size), table(_precompute_table(_data, _size))
    {
    }

    // Returns the partial sum of the data in the buffer which starts at 'begin'
    // (inclusive) and which stops at 'end' (excluded).
    partial_sum_t sum(size_t begin, size_t end) const;

    inline void prefetch(size_t begin, size_t end) const
    {
        size_t begin_div2 = begin / 2,
               end_div2   = end   / 2;
        __builtin_prefetch(this->table + end_div2);
        __builtin_prefetch(this->table + begin_div2);
    }

private:

    // Allocates and computes the one's complement sum table.
    static const uint16_t *_precompute_table(const void *_data, size_t _size);
};


// -----------------------------------------------------------------------------

//
// Checksum
//

struct checksum_t {
    net_t<uint16_t> value;

    // Checksum of an empty buffer.
    static const checksum_t ZERO;

    // Initializes the checksum to zero (checksum of an empty buffer).
    inline checksum_t(void)
    {
        this->value.net = 0;
    }

    // Computes the Internet Checksum of the given buffer.
    //
    // The Internet Checksum is the 16 bit ones' complement of the one's
    // complement sum of all 16 bit words in the given buffer.
    //
    // See [1] for the complete Internet checksum specification.
    //
    // The buffer is expected to be given in network byte order.
    // The returned 16 bits checksum will be in network byte order.
    //
    // [1]: http://tools.ietf.org/html/rfc1071
    inline checksum_t(const void *data, size_t size)
    {
        // The checksum is the ones' completent (e.g. binary not) of the 16 bits
        // ones' complement sum of every pair of bytes (16 bits).

        this->value.net = ~ _ones_complement_sum(data, size);
    }

    // Computes the Internet Checksum of the already computed ones' complement
    // sum.
    inline checksum_t(partial_sum_t partial_sum)
    {
        this->value.net = ~ partial_sum.sum;
    }

    // Returns 'true' if the value of the checksum is zero
    //
    // The Internet Checksum of an IPv4 datagram or a TCP segment has a zero
    // value when valid.
    inline bool is_valid(void)
    {
        return this->value.net == 0;
    }
} __attribute__ ((__packed__));

// -----------------------------------------------------------------------------

static inline uint16_t _swap_bytes(uint16_t bytes)
{
    return (bytes << 8) | (bytes >> 8);
}

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_CHECKSUM_HPP__ */
