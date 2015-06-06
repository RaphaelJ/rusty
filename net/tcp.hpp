//
// Provides functions to receive and send TCP segments.
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

#ifndef __TCP_MPIPE_NET_TCP_HPP__
#define __TCP_MPIPE_NET_TCP_HPP__

#include <tuple>

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

// TCP Control Block unique identifier.
//
// Each TCP connection is uniquely identified by the 4-tuple (remote address,
// remote port, local address, local port).
//
// As the destination address is unique for a TCP instance, each TCP Control
// Block can be uniquely identified using the 3-tuple (remote address, 
// remote port, local port).
template <typename addr_t, typename port_t>
struct tcp_tcb_id_t {
    addr_t  raddr;                      // Remote address
    port_t  rport;                      // Remote port
    port_t  lport;                      // Local port

    friend inline bool operator==(
        tcp_tcb_id_t<addr_t, port_t> a,
        tcp_tcb_id_t<addr_t, port_t> b
    )
    {
        return a.raddr == b.raddr && a.rport == b.rport && a.lport == b.lport;
    }

    friend inline bool operator!=(
        tcp_tcb_id_t<addr_t, port_t> a,
        tcp_tcb_id_t<addr_t, port_t> b
    )
    {
        return !(a == b);
    }
};

template <typename network_t>
struct tcp_t {
    //
    // Member types
    //

    typedef tcp_t<network_t>                this_t;

    typedef typename network_t::addr_t      addr_t;

    typedef uint16_t                        port_t;

    typedef uint32_t                        seq_t;

    typedef typename network_t::cursor_t    cursor_t;

    struct listen_t {
    };

    typedef tcp_tcb_id_t<addr_t, port_t>    tcb_id_t;

    struct tcb_t {
    };

    struct header_t {
        net_t<port_t>   sport;              // Source port
        net_t<port_t>   dport;              // Destination port
        net_t<seq_t>    seqnum;             // Sequence number
        net_t<seq_t>    acknum;             // Acknowledgement number

        //
        // Flags
        //

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t    res1:4;
            uint16_t    doff:4;
            uint16_t    fin:1;
            uint16_t    syn:1;
            uint16_t    rst:1;
            uint16_t    psh:1;
            uint16_t    ack:1;
            uint16_t    urg:1;
            uint16_t    res2:2;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t    doff:4;
            uint16_t    res1:4;
            uint16_t    res2:2;
            uint16_t    urg:1;
            uint16_t    ack:1;
            uint16_t    psh:1;
            uint16_t    rst:1;
            uint16_t    syn:1;
            uint16_t    fin:1;
        #else
            #error "Please fix __BYTE_ORDER in <bits/endian.h>"
        #endif

        net_t<uint16_t> window;
        net_t<uint16_t> check;               // checksum
        net_t<uint16_t> urg_ptr;
    } __attribute__ ((__packed__));

    //
    // Static fields
    //

    static constexpr size_t             HEADERS_SIZE = sizeof (struct tcphdr);

    //
    // Fields
    //

    // Lower network layer instance.
    network_t                           *network;

    // Ports which are in the LISTEN state, passively waiting for client
    // connections.
    unordered_map<port_t, listen_t>     listens;

    // TCP Control Blocks
    unordered_map<tcb_id_t, tcb_t>      tcbs;

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

    // Listen for TCP connections on the given port.
    //
    // Create a backlog of the given initial size to log
    void listen(port_t port, size_t backlog)
    {
    }

private:

    // Returns the current sequence number which should be used in 
    seq_t _current_seqnum(void)
    {
        return 0;
    }

};

#undef TCP_COLOR
#undef TCP_DEBUG
#undef TCP_ERROR

} } /* namespace tcp_mpipe::net */

namespace std {

// 'std::hash<>' and 'std::equal_to<>' instances are required for TCB
// identifiers to be used in unordered containers.

using namespace tcp_mpipe::net;

template <>
template <typename addr_t, typename port_t>
struct hash<tcp_tcb_id_t<addr_t, port_t>> {
    inline size_t operator()(const tcp_tcb_id_t<addr_t, port_t> &tcb_id) const
    {
        return   hash<uint32_t>()(tcb_id.raddr)
               + hash<uint32_t>()(tcb_id.rport)
               + hash<uint32_t>()(tcb_id.lport);
    }
};

template <>
template <typename addr_t, typename port_t>
struct equal_to<tcp_tcb_id_t<addr_t, port_t>> {
    inline bool operator()(
        const tcp_tcb_id_t<addr_t, port_t>& a,
        const tcp_tcb_id_t<addr_t, port_t>& b
    ) const
    {
        return a == b;
    }
};

} /* namespace std */

#endif /* __TCP_MPIPE_NET_TCP_HPP__ */
