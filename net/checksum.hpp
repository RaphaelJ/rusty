//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Computes a checksum required by IPv4 and TCP protocols.
//

#ifndef __TCP_MPIPE_NET_CHECKSUM_HPP__
#define __TCP_MPIPE_NET_CHECKSUM_HPP__

#include <cstdint>

namespace tcp_mpipe {
namespace net {

// Returns the 16 bit one's complement of the one's complement sum of all 16 bit
// words in the given buffer.
//
// The buffer is excpected to be given in network byte order.
// The returned 16 bits checksum will be in network byte order.
uint16_t checksum(const void *data, size_t size);

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_CHECKSUM_HPP__ */
