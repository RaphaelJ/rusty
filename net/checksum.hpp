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

//
// Partial sum
//

// Partially computed checksums.
//
// Can be computed with 'partial_sum()' and combined with an other partially
// computed sum with 'partial_sum_append()'. The checksum can be then computed
// from the partially computed sum with 'checksum()'.
struct partial_sum_t {
    uint16_t    sum;

    // 'true' when the sum has been computed on an odd number of bytes.
    bool        odd;
};

inline partial_sum_t partial_sum(const void *data, size_t size)
{
    return { _ones_complement_sum(data, size), (bool) (size & 0x1) };
}

// Returns the partial sum that would have been obtained if the buffer of the
// current sum and the buffer of the given partial sum were attached.
inline partial_sum_t partial_sum_append(
    partial_sum_t first, partial_sum_t second
)
{
    uint32_t sum = first.sum;

    // When the first sum was computed on an odd number of bytes, we virtually
    // added a zero byte to the buffer. We need to swap the bytes of the second
    // sum to cancel this padding.
    if (first.odd)
        sum += _swap_bytes(second.sum);
    else
        sum += second.sum;

    sum += sum >> 16; // Carry bit.

    return { (uint16_t) sum, first.odd != second.odd };
}

// -----------------------------------------------------------------------------

//
// Checksum
//

typedef net_t<uint16_t> checksum_t;

// Computes the Internet Checksum of the given buffer.
//
// The Internet Checksum is the 16 bit ones' complement of the one's complement
// sum of all 16 bit words in the given buffer.
//
// See [1] for the complete Internet checksum specification.
//
// The buffer is expected to be given in network byte order.
// The returned 16 bits checksum will be in network byte order.
//
// [1]: http://tools.ietf.org/html/rfc1071
inline checksum_t checksum(const void *data, size_t size)
{
    // The checksum is the ones' completent (e.g. binary not) of the 16 bits
    // ones' complement sum of every pair of bytes (16 bits).

    net_t<uint16_t> checksum_net;
    checksum_net.net = ~ _ones_complement_sum(data, size);
    return checksum_net;
}

// Computes the Internet Checksum of the already computed ones' complement sum.
inline checksum_t checksum(partial_sum_t partial_sum)
{
    net_t<uint16_t> checksum_net;
    checksum_net.net = ~ partial_sum.sum;
    return checksum_net;
}

// -----------------------------------------------------------------------------

static inline uint16_t _swap_bytes(uint16_t bytes)
{
    return (bytes << 8) | (bytes >> 8);
}

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_CHECKSUM_HPP__ */
