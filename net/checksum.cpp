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

#include "net/endian.hpp"   // net_t

#include "net/checksum.hpp"

namespace tcp_mpipe {
namespace net {

net_t<uint16_t> checksum(const void *data, size_t size)
{
    // The checksum is the one's completent (e.g. binary not) of the 16 bits
    // one's complement sum of every pair of bytes (16 bits). If the data has an
    // odd number of bytes, an additional zero byte is added as a padding.
    //
    // When a 16 bits one's complement addition produces a carry bit, the carry
    // must be added to the 16 bits result.
    //
    // As an example, here is the 4 bits one's complement addition of 1111 and
    // 1011:
    //
    //        1111
    //      + 1101
    //      ------
    //      1 1000
    //      \--------> The carry bit here must be added to the result (1000).
    //        1001 --> 4 bits one's complement addition of 1111 and 1011.
    //
    // The 16 bits one's complement checksum is thus equal to:
    //
    //      uint16_t *p = (uint16_t *) data;
    //
    //      // Computes the one's complement sum.
    //      uint32_t sum = 0;
    //      for (int i = 0; i < size / 2; i++) {
    //          sum += p[i];
    //
    //          if (sum >> 16) // if carry bit
    //              sum += 1;
    //      }
    //
    //      // The checksum is the binary negation (one's complement) of the 16
    //      // least significant bits of the sum.
    //      uint16_t checksum = ~((uint16_t) accumulator);
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
    //  _______________________________________________________________________
    // |   32 bits carry bits accumulator  | 2nd 16 bits sum | 1st 16 bits sum |
    //  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
    // \-----------------------------------------------------------------------/
    //                            64 bits accumulator
    //
    // It's not a problem that the least significant 16 bits sum produces a
    // carry bit as one's complement addition is commutative and as this carry
    // bit will be added to the second sum, which will be summed with first one
    // later.
    //
    // The algorithm then adds the 32 bits carry bits accumulator to the sum of
    // the two 16 bits sums to get the binary negation of the checksum.
    //
    // [1]:
    // microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html

    assert (data != nullptr && size >= 0);

    uint64_t sum = 0;
    const uint32_t *data32 = (const uint32_t *) data;

    // Sums 32 bits at a time.
    while (size > sizeof (uint32_t)) {
        sum += *data32; // NOTE: 'ntohl()' doesn't seem to be required

        data32++;
        size -= sizeof (uint32_t);
    }

    // Sums the last block which could not fit in an 32 bits integer.
    if (size > 0) {
        uint32_t word = 0;
        memcpy(&word, data32, size);
        sum += ntohl(word);
    }

    // 16 bits one's complement sums of two sub-sums and the carry bits.
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    net_t<uint16_t> sum_net;
    sum_net.net = ~sum;
    return sum_net;
}

} } /* namespace tcp_mpipe::net */
