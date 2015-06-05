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

// Returns the Internet Checksum of the given buffer.
//
// The Internet Checksum is the 16 bit one's complement of the one's complement
// sum of all 16 bit words in the given buffer.
//
// See [1] for the complete Internet checksum specification.
//
// The buffer is expected to be given in network byte order.
// The returned 16 bits checksum will be in network byte order.
//
// [1]: http://tools.ietf.org/html/rfc1071
net_t<uint16_t> checksum(const void *data, size_t size);

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_CHECKSUM_HPP__ */
