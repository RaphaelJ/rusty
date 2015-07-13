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

#include <algorithm>                // min
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>               // equal_to, hash
#include <map>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <utility>                  // pair, swap()

#include <netinet/tcp.h>            // TCPOPT_EOL, TCPOPT_NOP, TCPOPT_MAXSEG

#include "net/checksum.hpp"         // checksum(), partial_sum_t
#include "net/endian.hpp"           // net_t, to_host()
#include "util/macros.hpp"          // LIKELY(), UNLIKELY()

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
// But as the destination address is unique for a TCP instance, each TCP Control
// Block can be uniquely identified using the 3-tuple (remote address,
// remote port, local port).
template <typename addr_t, typename port_t>
struct tcp_tcb_id_t {
    net_t<addr_t>   raddr;                      // Remote address
    net_t<port_t>   rport;                      // Remote port
    net_t<port_t>   lport;                      // Local port

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

// TCP transport layer able to process segment from and to the specified network
// 'network_var_t' layer.
template <typename network_var_t>
struct tcp_t {
    //
    // Member types
    //

    // Redefines 'network_var_t' as 'network_t' so it can be accessible as a
    // member type.
    typedef network_var_t                           network_t;

    typedef tcp_t<network_t>                        this_t;

    typedef typename network_t::addr_t              addr_t;
    typedef uint16_t                                port_t;

    // Sequence number.
    struct seq_t {
        uint32_t    value;

        seq_t(void) { }

        seq_t(int _value) : value((uint32_t) _value) { }

        seq_t(uint16_t _value) : value((uint32_t) _value) { }

        seq_t(uint32_t _value) : value((uint32_t) _value) { }

        seq_t(size_t _value) : value((uint32_t) _value) { }

        // Unsigned arithmetic overflows in C reduced to the operation modulo
        // the largest type's integer plus one (4294967296). Thus we can expect
        // our sequence numbers to correctly wrap around when using standard
        // arithmetic operators. i.e '10 - 4294967295 = 11'.

        friend inline seq_t operator+(seq_t a, seq_t b)
        {
            return { a.value + b.value };
        }

        friend inline seq_t operator-(seq_t a, seq_t b)
        {
            return a.value - b.value;
        }

        inline seq_t operator++(void)
        {
            value++;
            return *this;
        }

        inline seq_t operator+=(seq_t other)
        {
            value += other.value;
            return *this;
        }

        friend inline bool operator==(seq_t a, seq_t b)
        {
            return a.value == b.value;
        }

        friend inline bool operator!=(seq_t a, seq_t b)
        {
            return a.value != b.value;
        }

        // Relative operators (used to check that a sequence number is inside a
        // window) require more attention . As the sequence number domain is
        // cyclic, a smaller sequence number can be greater than a  larger
        // sequence number. We consider that a sequence number is smaller than
        // another iff the difference between the number and the other is larger
        // than the half of the number of sequence numbers (> 2147483648).
        //
        // That is, 10 is larger than 4000000000, but 10 is smaller than
        // 2000000000.
        //
        // This idea has been taken from and used by lwIP.

        friend inline bool operator<(seq_t a, seq_t b)
        {
            return ((uint32_t) (a - b).value) < 0;
        }

        friend inline bool operator<=(seq_t a, seq_t b)
        {
            return ((uint32_t) (a - b).value) <= 0;
        }

        friend inline bool operator>(seq_t a, seq_t b)
        {
            return ((uint32_t) (a - b).value) < 0;
        }

        friend inline bool operator>=(seq_t a, seq_t b)
        {
            return ((uint32_t) (a - b).value) <= 0;
        }
    } __attribute__ ((__packed__));

    // Segment size.
    typedef uint16_t                                seg_size_t;

    // Maximum Segment Size
    typedef uint16_t                                mss_t;

    typedef uint16_t                                win_size_t;

    // TCP header tags.
    struct flags_t {
        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t     fin:1;
            uint8_t     syn:1;
            uint8_t     rst:1;
            uint8_t     psh:1;
            uint8_t     ack:1;
            uint8_t     urg:1;
            uint8_t     res:2;
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint8_t     res:2;
            uint8_t     urg:1;
            uint8_t     ack:1;
            uint8_t     psh:1;
            uint8_t     rst:1;
            uint8_t     syn:1;
            uint8_t     fin:1;
        #else
            #error "Please fix __BYTE_ORDER in <bits/endian.h>"
        #endif

        // Initializes all the flags to zero.
        inline flags_t(void)
        {
            memset(this, 0, sizeof (flags_t));
        }

        inline flags_t(
            uint8_t _urg, uint8_t _ack, uint8_t _psh, uint8_t _rst,
            uint8_t _syn, uint8_t _fin
        )
        {
            this->res = 0;
            this->urg = _urg;
            this->ack = _ack;
            this->psh = _psh;
            this->rst = _rst;
            this->syn = _syn;
            this->fin = _fin;
        }

        // Compares two flags but ignores the reserved field.
        friend inline bool operator==(flags_t a, flags_t b)
        {
            // Ignore the reserved field.
            a.res = 0;
            b.res = 0;

            return !memcmp(&a, &b, sizeof (flags_t));
        }
    } __attribute__ ((__packed__)) flags;

    struct header_t {
        net_t<port_t>       sport;      // Source port
        net_t<port_t>       dport;      // Destination port
        net_t<seq_t>        seq;        // Sequence number
        net_t<seq_t>        ack;        // Acknowledgement number

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t             res:4;
            uint8_t             doff:4; // Data offset. Number of 32 bits words
                                        // before the payload.
        #elif __BYTE_ORDER == __BIG_ENDIAN
            uint8_t             doff:4;
            uint8_t             res:4;
        #else
            #error "Please fix __BYTE_ORDER in <bits/endian.h>"
        #endif

        flags_t             flags;

        net_t<win_size_t>   window;
        checksum_t          check;
        net_t<uint16_t>     urg_ptr;
    } __attribute__ ((__packed__));

    struct options_t {
        enum mss_option_t : int {
            // Positive value: Option specified MSS.
            NO_MSS_OPTION   = -1
        } mss;

        size_t size(void)
        {
            if (mss != NO_MSS_OPTION)
                return 4;
            else
                return 0;
        }
    };

    typedef typename network_t::cursor_t            cursor_t;

    // Uniquely identifies a TCP Control Block or a connection.
    typedef tcp_tcb_id_t<addr_t, port_t>            tcb_id_t;

    // Callback called on an open connection when it receives data.
    typedef function<void(cursor_t)>                new_data_callback_t;

    // Callback called on new connections on a port open in the LISTEN state.
    //
    // The function is given the identifier of the new established connection.
    typedef function<new_data_callback_t(tcb_id_t)> new_connection_callback_t;

    // TCP Control Block.
    //
    // Contains information to track an established TCP connection. Each TCB is
    // uniquely identified by a 'tcb_id_t'.
    struct tcb_t {
        enum state_t : int {
            // Waiting for a matching connection request after having sent a
            // connection request.
            SYN_SENT     = 1 << 0,
            // Waiting for a confirming connection request acknowledgment after
            // having both received and sent a connection request.
            SYN_RECEIVED = 1 << 1,
            // Open connection, data received can be delivered to the user.
            ESTABLISHED  = 1 << 2,
            // Waiting for a connection termination request from the remote TCP,
            // or an acknowledgment of the connection termination request
            // previously sent.
            FIN_WAIT_1   = 1 << 3,
            // Waiting for a connection termination request from the remote TCP.
            FIN_WAIT_2   = 1 << 4,
            // Waiting for a connection termination request from the local user.
            CLOSE_WAIT   = 1 << 5,
            // Waiting for a connection termination request acknowledgment from
            // the remote TCP.
            CLOSING      = 1 << 6,
            // Waiting for an acknowledgment of the connection termination
            // request previously sent to the remote TCP (which includes an
            // acknowledgment of its connection termination request).
            LAST_ACK     = 1 << 7,
            // Waiting for enough time to pass to be sure the remote TCP
            // received the acknowledgment of its connection termination
            // request.
            TIME_WAIT    = 1 << 8
        } state;

        inline friend state_t operator|(state_t a, state_t b)
        {
            return (state_t) ((int) a | (int) b);
        }

        mss_t                   mss;    // Maximum segment size (TCP segment
                                        // payload, without headers).

        //
        // Sliding windows
        //

        // Receiver sliding window.
        //
        //     |> Next expected sequence number
        // ----+-------------------------------+-------------------------------
        //     |    Receiver sliding window    |
        // ----+-------------------------------+-------------------------------
        //     \-------------------------------/
        //               Window size
        struct rx_window_t {
            seq_t       init;   // Initial Sequence Number (ISN) of the remote.
            win_size_t  size;
            seq_t       next;   // Next sequence number expected to receive.

            // Returns 'true' if the given sequence number is inside this
            // receiver window (next <= seq < next + size).
            inline bool in_window(seq_t seq) const
            {
                return (seq - next).value < size;
            }

            // Returns 'true' if the received segment is acceptable with the
            // current state of the window as defined in RFC 793 (page 69):
            //
            // Length  Window   Segment Receive  Test
            // ------- -------  -------------------------------------------
            // 0       0        seq == next
            // 0       >0       next <= seq < next + size
            // >0      0        false
            // >0      >0          next <= seq < next + size
            //                  || next <= seq + payload_size - 1 < next + size
            inline bool acceptable_seg(seq_t seq, size_t payload_size) const
            {
                if (size >= 0)
                    return    in_window(seq)
                           || (   payload_size > 0
                               && in_window(seq + seq_t(payload_size) - 1));
                else
                    return payload_size == 0 && seq == next;
            }

            // Returns 'true' if the received segment contains at least the next
            // byte to receive
            // (payload_size > 0 && seq <= next < seq + payload_size).
            inline bool contains_next(seq_t seq, size_t payload_size) const
            {
                return payload_size > (next - seq).value;
            }
        } rx_window;

        // Transmitter (sender) sliding window.
        //
        //               |> First sent but unacknowledged byte
        //             Next sequence number to send <|
        //  -------------+---------------------------+--------------------+-----
        //  Acknowledged | Sent but not acknowledged | Not sent but ready |
        //  -------------+---------------------------+--------------------+-----
        //               \------------------------------------------------/
        //                                  Window size
        struct tx_window_t {
            seq_t       init;   // Initial Sequence Number (ISN) of the local.
            win_size_t  size;
            seq_t       unack;  // First sent but unacknowledged byte.
            seq_t       next;   // Next sequence number to send.
            seq_t       wl1;    // Received sequence number of the last segment
                                // used to update 'size'.
            seq_t       wl2;    // Received acknowledgment number of the last 
                                // segment used to update 'size'.

            // Returns 'true' if the given sequence number is inside this
            // receiver window (unack <= seq <= unack + size).
            inline bool in_window(seq_t seq) const
            {
                return (seq - unack).value < size;
            }

            // Returns 'true' if the given sequence number is something already
            // sent but not yet acknowledged (unack < ack <= next).
            inline bool acceptable_ack(seq_t ack) const
            {
                return unack < ack && ack <= next;
            }

            // Updates the sender window size and the values of 'wl1' and 'wl2'
            // if 'wl1 < seq || (wl1 == seq && wl2 <= ack)' (this prevents old
            // segments to update the window).
            void update_window_size(seq_t seq, seq_t ack, win_size_t size)
            {
                if (wl1 < seq || (wl1 == seq && wl2 <= ack)) {
                    size = size;
                    wl1  = seq;
                    wl2  = ack;
                }
            }
        } tx_window;

        //
        // Receiving queue
        //

        // Contains a segment's payload (without TCP headers) which has been
        // delivered out of order.
        //
        // The 'seq_t' key gives the segment number of the first byte of the 
        // cursor.
        struct out_of_order_segment_t {
            seq_t       seq;
            cursor_t    payload;
        };

        // Contains segment payloads which have not been transmitted to the
        // application layer nor acknowledged because they have been delivered
        // out of order.
        vector<out_of_order_segment_t>  out_of_order;

        // Function provided by the application layer which will be called each
        // time new data is received.
        new_data_callback_t             new_data_callback;

        //
        // Transmission queue
        //
        // The queue contains entries which are waiting to be sent and entries
        // which have been sent but not acknowledged.
        //
        // The queue is composed of functions instead of buffer. These functions
        // are able to write a determined amount of bytes in network buffers
        // just before the transmission.
        //

        // A queue entry contains a function able to write data from 'seq' to
        // 'seq' + 'size'. The 'acked' function is called once the whole entry
        // has been transmitted and acknowledged.
        struct tx_queue_entry_t {
            seq_t                               seq;
            size_t                              size;

            // Function provided by the user to write data into transmission
            // buffers. The first function argument gives the offset (against
            // 'seq'). The number of bytes to write is given by the cursor size.
            //
            // The function could be called an undefined number of times because
            // of packet segmentation and retransmission.
            function<void(size_t, cursor_t)>    writer;

            // Function which is called once all the data provided by the writer
            // has been acked and the queue entry removed.
            function<void()>                    acked;
        };

        // Transmission queue.
        //
        // Entries are sorted in increasing sequence number order and will be
        // removed once they have been fully acknowledged.
        queue<tx_queue_entry_t> tx_queue;

        inline bool in_state(state_t states)
        {
            return this->state & states;
        }
    };

    //
    // Static fields
    //

    static constexpr size_t     HEADER_SIZE = sizeof (header_t);

    static const     options_t  EMPTY_OPTIONS;

    // Maximum number of out of order segments which will be retained before
    // starting to drop them.
    //
    // NOTE: current implementation is not efficient (quadradic against the
    // number of out of order segments), but shouldn't be an issue as storing a
    // large a number of out of order segments is not appealing (Linux use 3 as
    // default value).
    static constexpr size_t     MAX_OUT_OF_ORDER_SEGS   = 5;

    //
    // Fields
    //

    // Lower network layer instance.
    network_t                                               *network;

    // Ports which are in the LISTEN state, passively waiting for client
    // connections.
    //
    // Each open port maps to a callback function provided by the application to
    // handle new connections.
    unordered_map<net_t<port_t>, new_connection_callback_t> listens;

    // TCP Control Blocks for active connections.
    unordered_map<tcb_id_t, tcb_t>                          tcbs;

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

    #define IGNORE_SEGMENT(WHY, ...)                                           \
        do {                                                                   \
            TCP_ERROR(                                                         \
                "Segment from %s:%" PRIu16 " ignored: " WHY,                   \
                network_t::addr_t::to_alpha(saddr), hdr->sport.host(),         \
                ##__VA_ARGS__                                                  \
            );                                                                 \
            return;                                                            \
        } while (0)

    // Processes a TCP segment from the given network address. The segment must
    // start at the given cursor (network layer payload without headers).
    //
    // Usually called by the network layer.
    void receive_segment(net_t<addr_t> saddr, cursor_t cursor)
    {
        size_t seg_size = cursor.size();

        if (UNLIKELY(seg_size < HEADER_SIZE)) {
            TCP_ERROR("Segment ignored: too small to hold a TCP header");
            return;
        }

        // Computes the pseudo-header sum before reading the header and the
        // payload.
        partial_sum_t partial_sum = network_t::tcp_pseudo_header_sum(
            saddr, this->network->addr, net_t<seg_size_t>(seg_size)
        );

        cursor.template read_with<header_t, void>(
        [this, saddr, seg_size, &partial_sum]
        (const header_t *hdr, cursor_t payload) {
            //
            // Checks and processes the TCP header.
            //

            if (UNLIKELY(hdr->doff < HEADER_SIZE / sizeof (uint32_t)))
                IGNORE_SEGMENT("data offset to small to contain the header");

            // Computes and checks the final checksum by adding the sum of the
            // header and of the payload.

            partial_sum = partial_sum.append(partial_sum_t(hdr, HEADER_SIZE))
                                     .append(partial_sum_t(payload));

            checksum_t checksum = checksum_t(partial_sum);

            if (UNLIKELY(!checksum.is_valid()))
                IGNORE_SEGMENT("invalid TCP checksum");

            //
            // Processes TCP options.
            //

            _parse_options_status_t status;
            options_t options = _parse_options(hdr, &payload, &status);

            switch (status) {
            case OPTIONS_SUCCESS:
                break;
            case MALFORMED_OPTIONS:
                IGNORE_SEGMENT("malformed options");
                break;
            case INVALID_MSS:
                IGNORE_SEGMENT("invalid use of the MSS option");
                break;
            default:
                IGNORE_SEGMENT("invalid options");
            };

            //
            // Processes the TCP message.
            //

            TCP_DEBUG(
                "Receives a TCP segment from %s:%" PRIu16 " on port %" PRIu16,
                network_t::addr_t::to_alpha(saddr), hdr->sport.host(),
                hdr->dport.host()
            );

            // Processes the segment with the handler corresponding to the
            // current state of the TCP connection.
            //
            // The two LISTEN and CLOSED states are handled separatly as there
            // is no TCB for them.

            tcb_id_t tcb_id = { saddr, hdr->sport, hdr->dport };
            auto tcb_it = this->tcbs.find(tcb_id);

            if (tcb_it == this->tcbs.end()) {
                // No existing TCB for the connection.

                auto listen_it = this->listens.find(hdr->dport);

                if (LIKELY(listen_it != this->listens.end())) {
                    this->_handle_listen_state(
                        saddr, hdr, tcb_id, options, payload, &listen_it->second
                    );
                } else
                    this->_handle_closed_state(saddr, hdr, payload);
            } else {
                tcb_t *tcb = &tcb_it->second;

                if (tcb->in_state(tcb_t::SYN_SENT)) {
                    this->_handle_syn_sent_state(
                        saddr, hdr, payload, tcb_id, tcb
                    );
                } else {
                    this->_handle_other_states(
                        saddr, hdr, payload, tcb_id, tcb
                    );
                }
            }
        });
    }

    //
    // Server sockets.
    //

    // Starts listening for TCP connections on the given port.
    //
    // If the port was already in the listen state, replaces the previous
    // callback function.
    void listen(port_t port, new_connection_callback_t new_connection_callback)
    {
        this->listens.emplace(port, new_connection_callback);
    }

    //
    // Client sockets.
    //

    

private:

    // Common flags
    static const flags_t _SYN_FLAGS;        // <CTL=SYN>
    static const flags_t _SYN_ACK_FLAGS;    // <CTL=SYN, ACK>

    static const flags_t _ACK_FLAGS;        // <CTL=ACK>

    static const flags_t _RST_FLAGS;        // <CTL=RST>
    static const flags_t _RST_ACK_FLAGS;    // <CTL=RST, ACK>

    // -------------------------------------------------------------------------
    //
    // TCP state machine handlers.
    //
    // Each handler is responsible of the processing of a received segment with
    // the connection in the corresponding state.

    #define TCP_DEBUG_STATE_CHANGE(from, to)                                   \
        do {                                                                   \
            TCP_DEBUG(                                                         \
                "State change for %s:%" PRIu16 " on local port %" PRIu16 ": "  \
                from " -> " to, network_t::addr_t::to_alpha(saddr),            \
                hdr->sport.host(), hdr->dport.host()                           \
            );                                                                 \
        } while (0);

    //
    // LISTEN
    //

    void _handle_listen_state(
        net_t<addr_t> saddr, const header_t *hdr, tcb_id_t tcb_id,
        options_t options, cursor_t payload,
        const new_connection_callback_t *new_connection_callback
    )
    {
        if (UNLIKELY(hdr->flags.rst)) {
            // Ignore RST segments.
            IGNORE_SEGMENT("RST segment received while in LISTEN state");
        } else if (UNLIKELY(hdr->flags.ack)) {
            // There is nothing to be acknowledged in the LISTEN state.
            return this->_respond_with_rst_segment(saddr, hdr, payload);
        } else if (LIKELY(hdr->flags.syn)) {
            // SYN segment.
            //
            // Creates the TCB in the SYN-RECEIVED state and responds to the
            // segment with a SYN-ACK segment. Notifies the application of the
            // new connection.

            TCP_DEBUG_STATE_CHANGE("LISTEN", "SYN-RECEIVED");

            //
            // Creates an initializes the TCB.
            //

            seq_t irs = hdr->seq.host();        // Initial Receiver Sequence
                                                // number.
            seq_t iss = _get_current_tcp_seq(); // Initial Sender Sequence 
                                                // number.

            auto p = this->tcbs.emplace(
                piecewise_construct, forward_as_tuple(tcb_id),
                forward_as_tuple()
            );
            assert(p.second); // Emplace succeed.
            tcb_t *tcb = &p.first->second;

            tcb->state = tcb_t::SYN_RECEIVED;

            tcb->mss = this->network->max_payload_size - HEADER_SIZE;
            if (options.mss != options_t::NO_MSS_OPTION)
                tcb->mss = min(tcb->mss, (mss_t) options.mss);
            else {
                // RFC 1122 specifies that if no MSS option is used, the remote
                // MSS is assumed to be equal to 536.
                tcb->mss = min(tcb->mss, (mss_t) 536);
            }

            tcb->rx_window.init = irs;
            tcb->rx_window.size = tcb->mss;
            tcb->rx_window.next = irs + seq_t(1);

            tcb->tx_window.init  = iss;
            tcb->tx_window.size  = hdr->window.host();
            tcb->tx_window.unack = iss;
            tcb->tx_window.next  = iss + seq_t(1);

            //
            // Sends the SYN-ACK segment.
            //

            this->_send_syn_ack_segment(
                hdr->dport, saddr, hdr->sport, tcb, iss, tcb->rx_window.next,
                tcb->rx_window.size
            );

            //
            // Notifies the application.
            //

            // Copies the callback before calling it as it could be removed
            // while being called.
            new_connection_callback_t callback = *new_connection_callback;

            new_data_callback_t new_data_callback = callback(tcb_id);

            // As the new connection callback could have initiated a new
            // connection, and subsequently modified the 'tcbs' map, the 'tcb'
            // pointer is now potentially invalidated and must be reacquired
            // before assigning it the 'new_data_callback'.

            auto tcb_it = this->tcbs.find(tcb_id);

            // The TCB should always exist, even if the callback decided to
            // close the connection, in which case it moved into the FIN-WAIT-1
            // state.
            assert(tcb_it != this->tcbs.end());

            tcb = &tcb_it->second;
            tcb->new_data_callback = new_data_callback;

            // RFC 793 (page 66) specifies that any text included in the SYN
            // segment should be queued for processing later. "Later" is not
            // precisely defined, but I expect it to be "when in the ESTABLISHED
            // state".
            if (!payload.empty())
                this->_handle_out_of_order_payload(irs + 1, payload, tcb);
        } else {
            // Any other segment is not valid and should be ignored.
            IGNORE_SEGMENT("invalid segment");
        }
    }

    //
    // SYN-SENT
    //

    void _handle_syn_sent_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload,
        tcb_id_t tcb_id, tcb_t *tcb
    )
    {
        if (LIKELY(hdr->flags.ack)) {
            // If a segment contains an ACK field, we must check that it
            // acknowledges something we sent, whatever it's the SYN control
            // flag or any data we sent after.
            //
            // If the ACK number is out of the transmission window, the segment
            // comes from another connection and we respond with a RST segment
            // (unless it has an RST control bit).

            seq_t ack = hdr->ack.host();

            if (UNLIKELY(!tcb->tx_window.acceptable_ack(ack))) {
                // The segment doesn't not acknowledge something we sent,
                // probably a segment from an older connection.

                IGNORE_SEGMENT("unexpected ack number");

                if (!hdr->flags.rst)
                    return this->_respond_with_rst_segment(saddr, hdr, payload);
            } else if (UNLIKELY(hdr->flags.rst))
                return this->_destroy_tcb(tcb_id);
            else if (LIKELY(hdr->flags.syn)) {
                // Moves into the ESTABLISHED state and acknowledges the
                // received SYN segment.

                TCP_DEBUG_STATE_CHANGE("SYN-SENT", "ESTABLISHED");

                tcb->state = tcb_t::ESTABLISHED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.init = irs;
                tcb->rx_window.next = irs + seq_t(1);

                tcb->tx_window.size  = hdr->window.host();
                tcb->tx_window.unack = ack;

                size_t payload_size = payload.size();
                if (payload_size > 0) {
                    this->_handle_in_order_payload(
                        irs + 1, payload, payload_size, tcb
                    );
                }

                return this->_respond_with_ack_segment(saddr, hdr, tcb);
            } else
                IGNORE_SEGMENT("no SYN nor RST control bit");
        } else {
            // No ACK number.

            if (UNLIKELY(hdr->flags.rst)) {
                // This RST segment can not be reliably associated with the
                // current connection as it doesn't have an ACK number, ignore
                // it.
                IGNORE_SEGMENT(
                    "can't be associated with the current connection"
                );
            } else if (LIKELY(hdr->flags.syn)) {
                // Moves into the SYN-RECEIVED state and acknowledges the
                // segment by re-emiting a SYN-ACK segment.

                TCP_DEBUG_STATE_CHANGE("SYN-SENT", "SYN-RECEIVED");

                tcb->state = tcb_t::SYN_RECEIVED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.init = irs;
                tcb->rx_window.next = irs + 1;

                tcb->tx_window.size  = hdr->window.host();

                this->_send_syn_ack_segment(
                    hdr->dport, saddr, hdr->sport, tcb,
                    tcb->tx_window.next, tcb->rx_window.next, tcb->mss
                );

                if (!payload.empty()) {
                    this->_handle_out_of_order_payload(
                        irs + (seq_t) 1, payload, tcb
                    );
                }
            } else
                IGNORE_SEGMENT("no SYN nor RST control bit");
        }
    }

    //
    // CLOSED
    //

    void _handle_closed_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload
    )
    {
        if (LIKELY(!hdr->flags.rst)) {
            // Any RST segment received while in the CLOSED state should be
            // ignored to avoid infinite loops.
            this->_respond_with_rst_segment(saddr, hdr, payload);
        }
    }

    //
    // SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN- WAIT-2, CLOSE-WAIT,
    // CLOSING, LAST-ACK
    //

    void _handle_other_states(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload,
        tcb_id_t tcb_id, tcb_t *tcb
    )
    {
        // Implemented as specified in RFC 793 page 69 to 76.

        seq_t seq = hdr->seq.host();

        // Checks that the segment contains data which is in the receiving
        // window.
        if (UNLIKELY(!tcb->rx_window.acceptable_seg(seq, payload.size()))) {
            // Old duplicate.
            if (!hdr->flags.rst)
                this->_respond_with_ack_segment(saddr, hdr, tcb);

            IGNORE_SEGMENT("unexpected ack number");
        }

        if (UNLIKELY(hdr->flags.rst)) {
            // TODO: in SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 &
            // CLOSE-WAIT states, an error should be delivered to the
            // application layer.
            return this->_destroy_tcb(tcb_id);
        }

        if (UNLIKELY(hdr->flags.syn)) {
            // Only invalid SYN segment should reach this stage, as any
            // duplicate of the initial SYN segment should have been dropped
            // earlier.

            assert(seq != tcb->rx_window.init);

            this->_destroy_tcb(tcb_id);

            // TODO: A "connection reset" signal should be delivered to the
            // application layer.

            return this->_respond_with_rst_segment(saddr, hdr, payload);
        }

        if (UNLIKELY(!hdr->flags.ack)) {
            // Any segment in this state should have the ACK control bit set as
            // required by RFC 793 (page 72).
            IGNORE_SEGMENT("segment without the ACK control bit set");
        }

        //
        // Processes the acknowledgment number.
        //

        seq_t ack = hdr->ack.host();
        bool acceptable_ack = tcb->tx_window.acceptable_ack(ack);

        if (tcb->in_state(tcb_t::SYN_RECEIVED)) {
            if (LIKELY(acceptable_ack)) {
                // Our SYN has been acknowledged, moves into the ESTABLISHED
                // state.

                TCP_DEBUG_STATE_CHANGE("SYN-RECEIVED", "ESTABLISHED");

                tcb->state          = tcb_t::ESTABLISHED;
                tcb->tx_window.size = hdr->window.host();
                tcb->tx_window.wl1  = seq;
                tcb->tx_window.wl2  = ack;
            } else
                return this->_respond_with_rst_segment(saddr, hdr, payload);
        }

        // Could not be in the SYN-RECEIVED state anymore.
        assert(!tcb->in_state(tcb_t::SYN_RECEIVED));

        // Updates the transmission window according to the received ack number.
        if (tcb->in_state(
            tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2 |
            tcb_t::CLOSE_WAIT | tcb_t::CLOSING
        )) {
            if (LIKELY(acceptable_ack)) {
                tcb->tx_window.unack = ack;

                // Removes transmission queue entries which have been
                // acknowledged.
                while (!tcb->tx_queue.empty()) {
                    const typename tcb_t::tx_queue_entry_t *entry =
                        &tcb->tx_queue.front();

                    if (entry->seq + (seq_t) entry->size <= ack)
                        tcb->tx_queue.pop();
                    else
                        break;
                }

                tcb->tx_window.update_window_size(seq, ack, hdr->window.host());
            } else if (ack > tcb->tx_window.next) {
                // Acknowledgement of something not yet send.
                return this->_respond_with_ack_segment(saddr, hdr, tcb);
            } else if (ack == tcb->tx_window.unack) {
                // Duplicate segment, but it could contain a new window size.
                tcb->tx_window.update_window_size(seq, ack, hdr->window.host());
            }

            // When in the FIN-WAIT-1 state, if the FIN is acknowledged, enters
            // the FIN-WAIT-2 state.
            if (
                tcb->in_state(tcb_t::FIN_WAIT_1) && ack == tcb->tx_window.next
            ) {
                TCP_DEBUG_STATE_CHANGE("FIN-WAIT-1", "FIN-WAIT-2");
                tcb->state = tcb_t::FIN_WAIT_2;
            }

            // When in the FIN-WAIT-2 state, if the retransmission queue is
            // empty, the application layer can be notified that the connection
            // is closed.
            if (tcb->in_state(tcb_t::FIN_WAIT_2) && tcb->tx_queue.empty()) {
                // TODO
            }

            // When in the CLOSING state, if the FIN is acknowledged, enters
            // the TIME-WAIT state, otherwise, ignore the segment.
            if (tcb->in_state(tcb_t::CLOSING)) {
                if (ack == tcb->tx_window.next) {
                    TCP_DEBUG_STATE_CHANGE("CLOSING", "TIME-WAIT");
                    tcb->state = tcb_t::TIME_WAIT;
                } else
                    IGNORE_SEGMENT("in CLOSING state");
            }

        } else if (
            tcb->in_state(tcb_t::LAST_ACK) && ack == tcb->tx_window.next
        ) {
            // When in the LAST-ACK state, if our FIN is now acknowledged,
            // delete the TCB and return.
            return this->_destroy_tcb(tcb_id);
        }

        // When in the CLOSING state, if our FIN is now acknowledged, delete
        // the TCB and return.
        if (tcb->in_state(tcb_t::LAST_ACK) && ack == tcb->tx_window.next)
            return this->_destroy_tcb(tcb_id);

        // TODO: processes URG segments.

        //
        // Processes the segment text.
        //

        if (tcb->in_state(
            tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2
        ))
            this->_handle_payload(seq, payload, tcb);

        // TODO: send an acknowledgement

        //
        // Processes the FIN control bit.
        //

        if (hdr->flags.fin) {
            // TODO: notify the application layer that the connection is closing
            // and returns an error value for any new call to receive().

            ++tcb->rx_window.next;

            // Acknowledges the FIN.
            this->_respond_with_ack_segment(saddr, hdr, tcb);

            switch (tcb->state) {
            case tcb_t::ESTABLISHED:
                TCP_DEBUG_STATE_CHANGE("ESTABLISHED", "CLOSE-WAIT");
                tcb->state = tcb_t::CLOSE_WAIT;
                break;
            case tcb_t::FIN_WAIT_1:
                // We would already be in the FIN-WAIT-2 if our FIN was acked,
                // because of the previous ACK processing.
                //
                // The only way to reach this stage while being in the
                // FIN-WAIT-1 is by *not* having received an acknowledgment for
                // our FIN segment.

                assert(ack != tcb->tx_window.next);

                TCP_DEBUG_STATE_CHANGE("FIN-WAIT-1", "CLOSING");
                tcb->state = tcb_t::CLOSING;
                break;
            case tcb_t::FIN_WAIT_2:
                TCP_DEBUG_STATE_CHANGE("FIN-WAIT-2", "TIME-WAIT");
                tcb->state = tcb_t::TIME_WAIT;

                // TODO: Start the time-wait timer, turn off the other timers.
                break;
            case tcb_t::TIME_WAIT:
                // When in the TIME-WAIT state, this could only be a
                // retransmission of the FIN. Restart the 2 MSL timeout.

                break;
            default:
                // Remain in the same state.
                break;
            };
        }
    }

    #undef IGNORE_SEGMENT
    #undef TCP_DEBUG_STATE_CHANGE

    // -------------------------------------------------------------------------
    //
    // Handle payload in segments
    //

    // Delivers the given payload to the application if delivered in order,
    // stores it in the out of order database otherwise (if possible).
    //
    // The payload is expected to be non empty and to have acceptable bytes
    // (see 'acceptable_seg()').
    //
    // Doesn't send an acknowledgment segment but updates the receiver window
    // when the segment is received in order.
    void _handle_payload(seq_t seq, cursor_t payload, tcb_t *tcb)
    {
        size_t payload_size = payload.size();

        assert(payload_size > 0);
        assert(tcb->rx_window.acceptable_seg(seq, payload_size));

        if (tcb->rx_window.contains_next(seq, payload_size))
            this->_handle_in_order_payload(seq, payload, payload_size, tcb);
        else
            this->_handle_out_of_order_payload(seq, payload, tcb);
    }

    // Delivers the given in order payload to the application.
    //
    // The payload is expected to be non empty.
    //
    // Doesn't send an acknowledgment segment but updates the receiver window.
    void _handle_in_order_payload(
        seq_t seq, cursor_t payload, size_t payload_size, tcb_t *tcb
    )
    {
        assert(payload_size > 0);
        assert(tcb->rx_window.contains_next(seq, payload_size));

        this->_deliver_to_app_layer(seq, payload, payload_size, tcb);

        this->_check_out_of_order_payloads(tcb);
    }

    // Stores the segment's payload in the out of order database (if possible).
    //
    // The payload is expected to be non empty.
    void _handle_out_of_order_payload(seq_t seq, cursor_t payload, tcb_t *tcb)
    {
        assert(!payload.empty());

        if (tcb->out_of_order.size() < MAX_OUT_OF_ORDER_SEGS) {
            typename tcb_t::out_of_order_segment_t seg { seq, payload };
            tcb->out_of_order.push_back(seg);
        }

        // TODO: free the segment if not inserted.
    }

    // Checks for and processes any out of order segment which can now be
    // received.
    //
    // Updates the receiver sliding window for any delivered segment.
    void _check_out_of_order_payloads(tcb_t *tcb)
    {
        auto it = tcb->out_of_order.begin();

        while (it != tcb->out_of_order.end()) {
            size_t payload_size = it->payload.size();

            if (tcb->rx_window.contains_next(it->seq, payload_size)) {
                // Segment is now in order.

                this->_deliver_to_app_layer(
                    it->seq, it->payload, payload_size, tcb
                );

                // Removes the segment from the 'out_of_order' vector.
                swap(*it, tcb->out_of_order.back());
                tcb->out_of_order.pop_back();

                // TODO: free the segment.

                // Retries for others segments.
                return this->_check_out_of_order_payloads(tcb);
            } else if (!tcb->rx_window.acceptable_seg(it->seq, payload_size)) {
                // Segment is now out of the window.

                // TODO: free the segment.

                // Removes the segment from the 'out_of_order' vector and
                // continues if there is other segments in the vector.
                swap(*it, tcb->out_of_order.back());
                tcb->out_of_order.pop_back();
            } else
                it++;
        }
    }

    // Delivers the segment starting at the given segmentation number and
    // containing the given payload to the application layer. Updates the
    // receiving windows accordingly.
    //
    // The payload must contain at least the next byte to receive (see
    // 'rx_window_t::contains_next()').
    void _deliver_to_app_layer(
        seq_t seq, cursor_t payload, size_t payload_size, tcb_t *tcb
    )
    {
        assert(payload_size > 0);
        assert(!tcb->rx_window.contains_next(seq, payload_size));

        // Removes bytes which have already been received or which are after the
        // window.
        seq_t payload_offset = tcb->rx_window.next - seq;
        payload = payload.drop(payload_offset.value)
                         .take(tcb->rx_window.size);

        tcb->new_data_callback(payload);

        tcb->rx_window.next += seq_t(payload_size);
    }

    // -------------------------------------------------------------------------
    //
    // TCB handling helpers
    //

    // Destroy resources allocated to a TCP connection.
    void _destroy_tcb(tcb_id_t tcb_id)
    {
        // TODO
    }

    // -------------------------------------------------------------------------
    //
    // Segment helpers
    //

    void _send_syn_ack_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack, mss_t mss
    )
    {
        options_t options = { (typename options_t::mss_option_t) mss };
        this->_send_segment(
            sport, daddr, dport, seq, ack, _SYN_ACK_FLAGS,
            net_t<win_size_t>(tcb->rx_window.size), options
        );
    }

    void _send_ack_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        this->_send_segment(
            sport, daddr, dport, seq, ack, _ACK_FLAGS,
            net_t<win_size_t>(tcb->rx_window.size), EMPTY_OPTIONS
        );
    }

    // Responds to the received segment by acknowledging the most recently
    // received byte.
    //
    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>.
    void _respond_with_ack_segment(
        net_t<addr_t> saddr, const header_t *hdr, const tcb_t *tcb
    )
    {
        this->_send_ack_segment(
            hdr->dport, saddr, hdr->sport, tcb,
            tcb->tx_window.next, tcb->rx_window.next
        );
    }

    void _send_rst_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        this->_send_segment(
            sport, daddr, dport, seq, ack, _RST_ACK_FLAGS, 0, EMPTY_OPTIONS
        );
    }

    // Responds to a received segment with a RST segment.
    //
    // RFC 793 (page 65) defines that RST messages which respond to segments
    // with the ACK field *off* should acknowledge the received segment and
    // should have zero as sequence number:
    //
    //     <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    //
    // ... while responses to segments having the ACK field *on* should not
    // (strangely) acknowledge the received segment and just use the received
    // ACK number as sequence number:
    //
    //     <SEQ=SEG.ACK><CTL=RST>
    void _respond_with_rst_segment(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload
    )
    {

        net_t<seq_t> seq;
        net_t<seq_t> ack;
        flags_t flags;

        if (!hdr->flags.ack) {
            seq.net = 0;
            // SYN and FIN flags must be acknowledged and thus "consume" one
            // byte.
            ack     = hdr->seq + hdr->flags.syn + hdr->flags.fin
                               + payload.size();
            flags   = _RST_ACK_FLAGS;
        } else {
            seq     = hdr->ack;
            ack.net = 0;
            flags   = _RST_FLAGS;
        }

        this->_send_segment(
            hdr->dport, saddr, hdr->sport, seq, ack, flags, 0, EMPTY_OPTIONS
        );
    }

    // Pushes the given segment with its payload to the network layer.
    void _send_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, options_t options
    )
    {
        net_t<addr_t> saddr = this->network->addr;
        size_t seg_size = HEADER_SIZE + options.size();

        // Precomputes the sum of the pseudo header.
        partial_sum_t pseudo_hdr_sum =
            network_t::tcp_pseudo_header_sum(
                saddr, daddr, net_t<seg_size_t>(seg_size)
            );

        this->network->send_tcp_payload(
        daddr, seg_size,
        [sport, daddr, dport, seq, ack, flags, window, options, pseudo_hdr_sum]
        (cursor_t cursor) {
            // Delays the writing of the headers as the sum of the payload and
            // options is not yet known.
            cursor_t hdr_cursor = cursor;

            auto ret = _write_options(cursor.drop(HEADER_SIZE), options);
            cursor = ret.first;
            partial_sum_t options_sum = ret.second;

            partial_sum_t partial_sum = pseudo_hdr_sum.append(options_sum);

            _write_header(
                hdr_cursor, sport, dport, seq, ack, flags, window, partial_sum
            );
        });
    }

    // Writes the TCP header starting at the given buffer cursor.
    //
    // 'partial_sum' is the sum of the pseudo TCP header and of the payload.
    static cursor_t _write_header(
        cursor_t cursor, net_t<port_t> sport, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, partial_sum_t partial_sum
    );

    // -------------------------------------------------------------------------
    //
    // TCP options
    //

    enum _parse_options_status_t {
        OPTIONS_SUCCESS,
        MALFORMED_OPTIONS,
        INVALID_MSS         // Malformed or misused MSS option.
    };

    // Parses TCP options located after the header.
    //
    // The 'payload' cursor points to the first byte after the header and will
    // point to the first byte after the options once the function returns.
    static options_t _parse_options(
        const header_t *hdr, cursor_t *payload, _parse_options_status_t *status
    );

    // Writes the TCP options starting at the given buffer cursor.
    //
    // Returns the cursor to write data after the options and the partial sum of
    // the options.
    static pair<cursor_t, partial_sum_t> _write_options(
        cursor_t cursor, options_t options
    );

    static inline seq_t _get_current_tcp_seq(void);

    // -------------------------------------------------------------------------
};

//
// Initializes static fields and methods.
//

template <typename network_t>
const typename tcp_t<network_t>::options_t
tcp_t<network_t>::EMPTY_OPTIONS = {
    tcp_t<network_t>::options_t::NO_MSS_OPTION
};

// Initializes common flags.

template <typename network_t>
const typename tcp_t<network_t>::flags_t
tcp_t<network_t>::_SYN_FLAGS(0, 0, 0, 0, 1 /* SYN */, 0);

template <typename network_t>
const typename tcp_t<network_t>::flags_t
tcp_t<network_t>::_SYN_ACK_FLAGS(0, 1 /* ACK */, 0, 0, 1 /* SYN */, 0);

template <typename network_t>
const typename tcp_t<network_t>::flags_t
tcp_t<network_t>::_ACK_FLAGS(0, 1 /* ACK */, 0, 0, 0, 0);

template <typename network_t>
const typename tcp_t<network_t>::flags_t
tcp_t<network_t>::_RST_FLAGS(0, 0, 0, 1 /* RST */, 0, 0);

template <typename network_t>
const typename tcp_t<network_t>::flags_t
tcp_t<network_t>::_RST_ACK_FLAGS(0, 1 /* ACK */, 0, 1 /* RST */, 0, 0);

// Defines static methods.

template <typename network_t>
typename tcp_t<network_t>::cursor_t
tcp_t<network_t>::_write_header(
    cursor_t cursor, net_t<port_t> sport, net_t<port_t> dport,
    net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
    net_t<uint16_t> window, partial_sum_t partial_sum
)
{
    return cursor.template write_with<header_t>(
    [sport, dport, seq, ack, flags, window, partial_sum](header_t *hdr) {
        hdr->sport   = sport;
        hdr->dport   = dport;
        hdr->seq     = seq;
        hdr->ack     = ack;
        hdr->res     = 0;
        hdr->doff    = HEADER_SIZE / sizeof (uint32_t);
        hdr->flags   = flags;
        hdr->window  = window;
        hdr->check   = checksum_t::ZERO;
        hdr->urg_ptr = 0;

        hdr->check = checksum_t(
            partial_sum.append(partial_sum_t(hdr, HEADER_SIZE))
        );
    });
}

template <typename network_t>
typename tcp_t<network_t>::options_t
tcp_t<network_t>::_parse_options(
    const header_t *hdr, cursor_t *payload, _parse_options_status_t *status
)
{
    options_t options;
    options.mss = options_t::NO_MSS_OPTION;

    *status = OPTIONS_SUCCESS;

    size_t options_size = (hdr->doff * 4) - HEADER_SIZE;

    if (options_size <= 0)
        return options;

    *payload = payload->read_with(
    [flags = hdr->flags, status, &options, options_size]
    (const char *data_char) mutable {
        const uint8_t *data = (const uint8_t *) data_char;
        const uint8_t *end  = data + options_size;

        while (data < end) {
            uint8_t kind = data[0];

            switch (kind) {
            // End of options list
            case TCPOPT_EOL:
                goto stop_parsing;

            // No-operation option
            case TCPOPT_NOP:
                data++;
                continue;

            // Maximum segment size option
            case TCPOPT_MAXSEG:
                if (UNLIKELY(
                        data[1] != 4 || !flags.syn
                    || options.mss != options_t::NO_MSS_OPTION
                )) {
                    *status = INVALID_MSS;
                    goto stop_parsing;
                } else if (UNLIKELY(data + 4 > end)) {
                    *status = MALFORMED_OPTIONS;
                    goto stop_parsing;
                } else {
                    mss_t mss = to_host<mss_t>(((mss_t *) data)[1]);

                    options.mss = (typename options_t::mss_option_t) mss;

                    data += 4;
                    continue;
                }

            default:
                TCP_DEBUG("Unknwown option kind: %d. Ignore", kind);

                // TCP options with other than TCPOPT_EOL or TCPOPT_NOP
                // contain their length in their second byte.
                uint8_t length = data[1];
                if (UNLIKELY(data + length > end || length < 2)) {
                    *status = MALFORMED_OPTIONS;
                    goto stop_parsing;
                }

                data += length;
            };
        }

        stop_parsing:
        {
        }
    }, options_size);

    return options;
}
template <typename network_t>
pair<typename tcp_t<network_t>::cursor_t, partial_sum_t>
tcp_t<network_t>::_write_options(cursor_t cursor, options_t options)
{
    if (options.mss != options_t::NO_MSS_OPTION) {
        partial_sum_t partial_sum;

        cursor = cursor.write_with(
        [options, &partial_sum](char *data_char) {
            uint8_t *data = (uint8_t *) data_char;

            data[0]             = TCPOPT_MAXSEG;
            data[1]             = 4;
            ((mss_t *) data)[1] = to_network<mss_t>(options.mss);

            partial_sum = partial_sum_t(data_char, 4);
        }, 4);

        return { cursor, partial_sum };
    } else
        return { cursor, partial_sum_t::ZERO };
}

template <typename network_t>
inline typename tcp_t<network_t>::seq_t
tcp_t<network_t>::_get_current_tcp_seq(void)
{
    return network_t::data_link_t::phys_t::get_current_tcp_seq();
}

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
        return   hash<net_t<addr_t>>()(tcb_id.raddr)
               + hash<net_t<port_t>>()(tcb_id.rport)
               + hash<net_t<port_t>>()(tcb_id.lport);
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
