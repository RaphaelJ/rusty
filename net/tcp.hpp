//
// Receives, processes and and sends TCP segments.
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

#include <functional>
#include <queue>
#include <tuple>

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

template <typename network_var_t>
struct tcp_t {
    //
    // Member types
    //

    // Redefines 'network_var_t' as 'network_t' so it can be accessible as a
    // member type.
    typedef network_var_t                   network_t;

    typedef tcp_t<network_t>                this_t;

    typedef typename network_t::addr_t      addr_t;
    typedef uint16_t                        port_t;
    typedef uint32_t                        seq_t;
    typedef uint16_t                        seg_size_t;

    typedef typename network_t::cursor_t    cursor_t;

    struct listen_t {
    };

    typedef tcp_tcb_id_t<addr_t, port_t>    tcb_id_t;

    // TCP Control Block.
    //
    // Contains information to track a TCP connection. Each TCB is uniquely
    // identified by a 'tcb_id_t'.
    struct tcb_t {
        //
        // Sliding windows
        //

        // Receiver sliding window.
        //
        //     /-> Next expected sequence number
        // ----+-------------------------------+-------------------------------
        //     |    Receiver sliding window    |
        // ----+-------------------------------+-------------------------------
        //     \-------------------------------/
        //               Window size
        struct {
            uint16_t    size;
            seq_t       next;   // Next sequence number to receive.
        } rx_window;

        // Transmitter (sender) sliding window.
        //
        //               |> First byte sent but unacknowledged
        //             Next sequence number to send <|
        //  -------------+---------------------------+--------------------+-----
        //  Acknowledged | Sent but not acknowledged | Not sent but ready |
        //  -------------+---------------------------+--------------------+-----
        //               \------------------------------------------------/
        //                                  Window size
        struct {
            uint16_t    size;
            seq_t       unack;  // First unacknowledged byte.
            seq_t       next;   // Next sequence number to send.
        } tx_window;

        //
        // Transmission queue
        //
        // The queue is composed of functions which are able to write a
        // determined amount of bytes in network buffers.
        //

        // A queue entry contains a function which will write data from 'seq' to
        // 'seq' + 'size'. The 'acked' function will be called once the whole
        // entry has been transmitted and acknowledged.
        struct tx_queue_entry_t {
            seq_t                               seq;
            size_t                              size;

            // Function provided by the user to write data into transmission
            // buffers. The first function argument gives the offset, the number
            // of bytes to write is given by the cursor size.
            //
            // The function could be called an undefined number of times because
            // of packet segmentation and retransmission.
            function<void(size_t, cursor_t)>    writer;

            // Function which will be called once all the data provided by the
            // writer will be acked.
            function<void()>                    acked;
        };

        // Transmission queue.
        //
        // Entries are sorted in increasing sequence number order and will be
        // removed once they have been fully acknowledged.
        queue<tx_queue_entry_t> tx_queue;
    };

    struct header_t {
        net_t<port_t>   sport;              // Source port
        net_t<port_t>   dport;              // Destination port
        net_t<seq_t>    seq_num;            // Sequence number
        net_t<seq_t>    ack_num;            // Acknowledgement number

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
        checksum_t      check;
        net_t<uint16_t> urg_ptr;
    } __attribute__ ((__packed__));

    //
    // Static fields
    //

    static constexpr size_t             HEADERS_SIZE = sizeof (header_t);

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
    void receive_segment(net_t<addr_t> src, cursor_t cursor)
    {
        size_t seg_size = cursor.size();

        if (UNLIKELY(seg_size < HEADERS_SIZE)) {
            TCP_ERROR("Segment ignored: too small to hold a TCP header");
            return;
        }
        TCP_DEBUG("%d", _get_current_tcp_seq());

        // Computes the pseudo-header sum before reading the header and the
        // payload.
        partial_sum_t partial_sum = network_t::tcp_pseudo_header_sum(
            src, this->network->addr, net_t<seg_size_t>(seg_size)
        );

        cursor.template read_with<header_t, void>(
        [this, src, seg_size, &partial_sum]
        (const header_t *hdr, cursor_t payload) {
            //
            // Checks the TCP segment.
            //

            #define IGNORE_SEGMENT(WHY, ...)                                   \
                do {                                                           \
                    TCP_ERROR(                                                 \
                        "Segment from %s:%" PRIu16 " ignored: " WHY,           \
                        network_t::addr_t::to_alpha(src), hdr->sport.host(),   \
                        ##__VA_ARGS__                                          \
                    );                                                         \
                    return;                                                    \
                } while (0)

            partial_sum = partial_sum.append(partial_sum_t(hdr, HEADERS_SIZE));

            // Computes and checks the final checksum by adding the sum of the
            // payload.
            checksum_t checksum = checksum_t(
                partial_sum.append(partial_sum_t(payload))
            );
            if (UNLIKELY(!checksum.is_valid()))
                IGNORE_SEGMENT("invalid checksum");

            #undef IGNORE_SEGMENT

            //
            // Processes the TCP message.
            //

            TCP_DEBUG(
                "Receives a TCP segment from %s:%" PRIu16 " on port %" PRIu16,
                network_t::addr_t::to_alpha(src), hdr->sport.host(),
                hdr->dport.host()
            );

        });
    }

    // Listen for TCP connections on the given port.
    //
    // Create a backlog of the given initial size to log
    void listen(port_t port, size_t backlog)
    {
    }

private:

    inline seq_t _get_current_tcp_seq(void)
    {
        return network_t::data_link_t::phys_t::get_current_tcp_seq();
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
