//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to receive and send TCP segments.
//

#ifndef __TCP_MPIPE_NET_TCP_HPP__
#define __TCP_MPIPE_NET_TCP_HPP__

#include <netinet/tcp.h>    // tcphdr

#include "net/checksum.hpp" // checksum()
#include "net/endian.hpp"   // net_t

using namespace std;

namespace tcp_mpipe {
namespace net {

#define TCP_COLOR     COLOR_MAG
#define TCP_DEBUG(MSG, ...)                                                    \
    TCP_MPIPE_DEBUG("TCP", TCP_COLOR, MSG, ##__VA_ARGS__)
#define TCP_ERROR(MSG, ...)                                                    \
    TCP_MPIPE_ERROR("TCP", TCP_COLOR, MSG, ##__VA_ARGS__)

template <typename network_t>
struct tcp_t {
    //
    // Member types
    //

    typedef tcp_t<network_t>                this_t;

    typedef typename network_t::cursor_t    cursor_t;

    //
    // Static fields
    //

    static constexpr size_t     HEADERS_SIZE = sizeof (struct tcphdr);

    //
    // Fields
    //

    // Lower network layer instance.
    network_t                   *network;

//     // Ports which are listening for client connections.
//     unordered_map<uint16_t, listen_t>     listen;

//     // TCP Control Block
//     unordered_map<uint16_t, listen_t>     listen;

    //
    // Methods
    //

    // Creates an TCP environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    tcp_t(void)
    {
    }

    // Creates a TCP environment for the given network layer instance.
    //
    // Does the same thing as creating the environment with 'tcp_t()' and then
    // calling 'init()'.
    tcp_t(network_t *_network) : network(_network)
    {
    }

    // Initializes a TCP environment for the given network layer instance.
    void init(network_t *_network)
    {
        network = _network;
    }

    // Processes a TCP segment from the given network address wich starts at the
    // given cursor (network layer payload without headers).
    void receive_segment(net_t<typename network_t::addr_t> src, cursor_t cursor)
    {
        size_t cursor_size = cursor.size();

        if (UNLIKELY(cursor_size < HEADERS_SIZE)) {
            TCP_ERROR("Segment ignored: too small to hold a TCP header");
            return;
        }

        cursor.template read_with<struct tcphdr, void>(
        [this, cursor_size](const struct tcphdr *hdr, cursor_t payload) {
            #define IGNORE_SEGMENT(WHY, ...)                                   \
                do {                                                           \
                    TCP_ERROR(                                                 \
                        "Segment from %s:%" PRIu16 " ignored: " WHY,           \
                        network_t::addr_to_alpha(src), ##__VA_ARGS__           \
                    );                                                         \
                    return;                                                    \
                } while (0)

            #undef IGNORE_SEGMENT
        });
    }
};

#undef TCP_COLOR
#undef TCP_DEBUG
#undef TCP_ERROR

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_TCP_HPP__ */
