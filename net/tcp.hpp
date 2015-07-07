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
#include <utility>                  // pair

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
    //
    // Unsigned arithmetic overflows in C reduced to the operation modulo the
    // largest type's integer plus one. Thus we can expect our sequence numbers
    // to correctly wrap around when using standard arithmetic operators.
    //
    // The only thing one must pay attention is how to check that a sequence
    // number is inside a window.
    typedef uint32_t                                seq_t;

    // Segment size.
    typedef uint16_t                                seg_size_t;

    // Maximum Segment Size
    typedef uint16_t                                mss_t;

    typedef uint16_t                                win_size_t;

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
        enum state_t {
            SYN_SENT,       // Waiting for a matching connection request after
                            // having sent a connection request.
            SYN_RECEIVED,   // Waiting for a confirming connection request
                            // acknowledgment after having both received and
                            // sent a connection request.
            ESTABLISHED,    // Open connection, data received can be delivered
                            // to the user.
            FIN_WAIT_1,     // Waiting for a connection termination request
                            // from the remote TCP, or an acknowledgment of the
                            // connection termination request previously sent.
            FIN_WAIT_2,     // Waiting for a connection termination request
                            // from the remote TCP.
            CLOSE_WAIT,     // Waiting for a connection termination request
                            // from the local user.
            CLOSING,        // Waiting for a connection termination request
                            // acknowledgment from the remote TCP.
            LAST_ACK        // Waiting for an acknowledgment of the connection
                            // termination request previously sent to the remote
                            // TCP (which includes an acknowledgment of its
                            // connection termination request).
        } state;

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
                seq_t end = next + size;
                if (next < end) // No sequence number overflow
                    return seq >= next && seq < end;
                else
                    return seq >= next || seq < end;
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
            inline bool acceptable_seq(seq_t seq, size_t payload_size) const
            {
                if (size >= 0)
                    return    in_window(seq)
                           || (   payload_size > 0
                               && in_window(seq + payload_size - 1));
                else
                    return payload_size == 0 && seq == next;
            }

            // Returns 'true' if the received segment contains at least the next
            // byte to receive
            // (payload_size > 0 && seq <= next < seq + payload_size).
            inline bool contains_next(seq_t seq, size_t payload_size) const
            {
                seq_t end = seq + payload_size;
                if (seq < end) // No sequence number overflow
                    return /* payload_size > 0 && */ next >= seq && next < end;
                else
                    return next >= seq || next < end;
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

            // Returns 'true' if the given sequence number is inside this
            // receiver window (unack <= seq <= unack + size).
            inline bool in_window(seq_t seq) const
            {
                if (unack < unack + size) // No sequence number overflow
                    return seq >= unack && seq < unack + size;
                else
                    return    seq >= unack
                           || seq < size - (UINT32_MAX - unack + 1);
            }

            // Returns 'true' if the given sequence number is something already
            // sent but not yet acknowledged (unack < ack <= next).
            inline bool acceptable_ack(seq_t ack) const
            {
                if (unack <= next) // No sequence number overflow
                    return ack > unack && ack <= next;
                else
                    return ack > unack || ack <= next;
            }
        } tx_window;

        //
        // Receiving queue
        //

        // Contains segment payloads which have not been transmitted to the
        // application layer nor acknowledged as they have been delivered out of
        // order. The 'seq_t' key gives the segment number of the first byte of
        // the cursor.
        map<seq_t, cursor_t>    out_of_order;

        // Function provided by the application layer which will be called each
        // time new data is received.
        new_data_callback_t     new_data_callback;

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
    };

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

    //
    // Static fields
    //

    static constexpr size_t     HEADER_SIZE = sizeof (header_t);

    static const     options_t  EMPTY_OPTIONS;

    // Maximum number of out of order segments which will be retained before
    // starting to drop them.
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

                switch (tcb->state) {
                case tcb_t::SYN_SENT:
                    this->_handle_syn_sent_state(
                        saddr, hdr, payload, tcb_id, tcb
                    );
                    break;
                case tcb_t::SYN_RECEIVED:
                    this->_handle_syn_received_state(
                        saddr, hdr, payload, tcb_id, tcb
                    );
                    break;
                case tcb_t::ESTABLISHED:
                    this->_handle_established_state(
                        saddr, hdr, payload, tcb_id, tcb
                    );
                    break;
                case tcb_t::FIN_WAIT_1:
                    this->_handle_fin_wait_1_state(hdr);
                    break;
                case tcb_t::FIN_WAIT_2:
                    this->_handle_fin_wait_2_state(hdr);
                    break;
                case tcb_t::CLOSE_WAIT:
                    this->_handle_close_wait_state(hdr);
                    break;
                case tcb_t::CLOSING:
                    this->_handle_closing_state(hdr);
                    break;
                case tcb_t::LAST_ACK:
                    this->_handle_last_ack_state(hdr);
                    break;
                };
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
            tcb->rx_window.next = irs + 1;

            tcb->tx_window.init  = iss;
            tcb->tx_window.size  = hdr->window.host();
            tcb->tx_window.unack = iss;
            tcb->tx_window.next  = iss + 1;

            //
            // Sends the SYN-ACK segment.
            //

            this->_send_syn_ack_segment(
                hdr->dport, saddr, hdr->sport, iss, tcb->rx_window.next,
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

            // TODO: handle potential payload

            return;
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
            // flag or any data we sent.
            //
            // If the ACK number is out of the transmission window, the segment
            // comes from another connection and we respond with a RST segment
            // (unless it has an RST control bit).

            seq_t ack = hdr->ack.host();

            if (UNLIKELY(
                   !tcb->tx_window.acceptable_ack(ack)
                || ack == tcb->tx_window.init
            )) {
                // The segment doesn't not acknowledge something we sent,
                // probably a segment from an older connection.

                if (!hdr->flags.rst)
                    return this->_respond_with_rst_segment(saddr, hdr, payload);
                else
                    IGNORE_SEGMENT("unexpected ack number");
            } else if (UNLIKELY(hdr->flags.rst))
                return this->_destroy_tcb(tcb_id);
            else if (LIKELY(hdr->flags.syn)) {
                // Moves into the ESTABLISHED state and acknowledges the
                // received SYN segment.

                tcb->state = tcb_t::ESTABLISHED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.init = irs;
                tcb->rx_window.next = irs + 1;

                tcb->tx_window.size  = hdr->window.host();
                tcb->tx_window.unack = ack;

                this->_send_ack_segment(
                    hdr->dport, saddr, hdr->sport,
                    tcb->tx_window.next, tcb->rx_window.next
                );

                // TODO: Must handle any data in the segment as if it was
                // delivered while in the ESTABLISHED state.
            } else
                IGNORE_SEGMENT("no SYN nor RST control bit");
        } else {
            // No ACK number.

            if (UNLIKELY(hdr->flags.rst)) {
                // This RST segment can not be reliably associated with the
                // current connection as it doesn't have an ACK number, ignore
                // it.
                IGNORE_SEGMENT(
                    "can not be associated with the current connection"
                );
            } else if (LIKELY(hdr->flags.syn)) {
                // Moves into the SYN-RECEIVED state and acknowledges the
                // segment by re-.
                tcb->state = tcb_t::SYN_RECEIVED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.init = irs;
                tcb->rx_window.next = irs + 1;

                tcb->tx_window.size  = hdr->window.host();

                this->_send_syn_ack_segment(
                    hdr->dport, saddr, hdr->sport,
                    tcb->tx_window.next, tcb->rx_window.next, tcb->mss
                );

                // TODO: if there is any data in the segment, its processing
                // must be delayed until the state machine reaches the
                // ESTABLISHED state.
            } else
                IGNORE_SEGMENT("no SYN nor RST control bit");
        }
    }

    //
    // SYN-RECEIVED
    //

    void _handle_syn_received_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload,
        tcb_id_t tcb_id, tcb_t *tcb
    )
    {
        seq_t seq = hdr->seq.host();

        // Checks that the segment contains data which is in the receiving
        // window.
        if (UNLIKELY(!tcb->rx_window.acceptable_seq(seq, payload.size()))) {
            if (!hdr->flags.rst) {
                // Old duplicate
                return this->_respond_with_ack_segment(saddr, hdr, tcb);
            } else
                IGNORE_SEGMENT("unexpected ack number");
        }

        if (UNLIKELY(seq != tcb->rx_window.next)) {
            // Segment received out of order.
            //
            // We could held it and reorder it later, but it's simpler to just
            // ignore it and to send a second acknowledgment of the last byte
            // we received.
            IGNORE_SEGMENT("out of order segment");
            return this->_respond_with_ack_segment(saddr, hdr, tcb);
        }

        if (UNLIKELY(hdr->flags.rst))
            return this->_destroy_tcb(tcb_id);

        if (UNLIKELY(hdr->flags.syn)) {
            // SYN segment should reach this stage as any duplicate of the
            // initial SYN segment should have been dropped earlier.

            assert(seq != tcb->rx_window.init);

            this->_destroy_tcb(tcb_id);
            return this->_respond_with_rst_segment(saddr, hdr, payload);
        }

        if (UNLIKELY(!hdr->flags.ack)) {
            // Any segment in this state should have the acknowledgment control
            // bit on as required by RFC 793 (page 72).
            IGNORE_SEGMENT("segment without the ACK control bit on");
        }

        seq_t ack = hdr->ack.host();

        if (UNLIKELY(!tcb->tx_window.acceptable_ack(ack)))
            return this->_respond_with_rst_segment(saddr, hdr, payload);

        if (!hdr->flags.fin) {
            // Moves into the ESTABLISHED state and acknowledges the
            // received SYN segment.

            tcb->state = tcb_t::ESTABLISHED;

            tcb->tx_window.size  = hdr->window.host();
            tcb->tx_window.unack = ack;

            // TODO: any data received in this segment must be processed as it
            // was sent while in the ESTABLISHED state.
        } else {
            // TODO: enters CLOSE-WAIT state.
        }
    }

    //
    // ESTABLISHED
    //

    void _handle_established_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload,
        tcb_id_t tcb_id, tcb_t *tcb
    )
    {

    }

    //
    // FIN-WAIT-1
    //

    void _handle_fin_wait_1_state(const header_t *hdr)
    {
    }

    //
    // FIN-WAIT-2
    //

    void _handle_fin_wait_2_state(const header_t *hdr)
    {
    }

    //
    // CLOSE-WAIT
    //

    void _handle_close_wait_state(const header_t *hdr)
    {
    }

    //
    // CLOSING
    //

    void _handle_closing_state(const header_t *hdr)
    {
    }

    //
    // LAST-ACK
    //

    void _handle_last_ack_state(const header_t *hdr)
    {
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

    #undef IGNORE_SEGMENT

    // -------------------------------------------------------------------------
    //
    // Handle payload in segments
    //

    void _handle_payload(seq_t seq, cursor_t payload, tcb_t *tcb)
    {
        if (tcb->rx_window.contains_next(seq)) {
            // In order segment.
//             tcb->new_data_callback();


        } else {
            // Out of order segment.
            this->_handle_out_of_order_payload(seq, payload, tcb);
        }
    }

    void _handle_out_of_order_payload(seq_t seq, cursor_t payload, tcb_t *tcb)
    {
        if (tcb->out_of_order.size() >= MAX_OUT_OF_ORDER_SEGS) {
            // Too many out of order segments have been accumulated, drops the
            // current segment.
            return;
        }

        // While inserting the new segment, we must check that no previously
        // inserted segment does provide the same data, and if the new segment
        // can replace some previously inserted segment.

        size_t size = payload.size();
        seq_t end = seq + size;

        assert(size > 0);

        auto it = tcb->out_of_order.lower_bound(seq);

        // Checks if no segment starting at or before the new segment's sequence
        // number entirely overlap the new segment.
        //r
        // If no previously inserted segment overlap, we insert the new segment.
        if (it != tcb->out_of_order.end() && it->first == seq) {
            // A segment starting at the same sequence number already exists.
            //
            // Only the largest of the two segments will be held.

            seq_t  seq_match  = it->first;
            size_t size_match = it->second.size();

            if (size > size_match) {
                // Replaces the previous segment by the current segment
                // which fully overlaps the matching segment.

                it->second = payload;

                // TODO: free the previous segment.
            } else {
                // The current segment payload is already entirely contained
                // by a single previously received segment, ignore it

                // TODO: free the current segment.
                return;
            }

            it++;
        } else {
            // No previously inserted segment starts at the same sequence
            // number.
            //
            // This doesn't mean that a segment with a lower sequence number
            // doesn't entirely overlap the new segment we are trying to insert.
            //
            // The following loop checks that no segment with a lower sequence
            // number entirely overlaps the new segment we are trying to insert.

            typename map<seq_t, cursor_t>::reverse_iterator rev_it(it);

            while (rev_it != tcb->out_of_order.rend()) {
                seq_t  seq_match  = rev_it->first;
                size_t size_match = rev_it->second.size();
                seq_t  end_match  = seq_match + size_match;

                assert(seq_match < seq);

                if (end_match <= end) {
                    // No segment overlap. Stop.
                    break;
                } else if (end_match >= end) {
                    // A previous segment entirely overlaps the segment we are
                    // trying to insert, the segment we are trying to insert is
                    // useless.

                    // TODO: free the current segment.
                    return;
                }

                rev_it++;
            }

            // No segment entirely overlaps, we can insert the segment.
            it = tcb->out_of_order.insert(
                it, pair<seq_t, cursor_t>(seq, payload)
            );
        }

        // We either inserted our segment or replaced another segment which
        // started at the same sequence number.
        //
        // We must now remove any following segment that is overlapped by the
        // segment we placed.

        while (it != tcb->out_of_order.end() && it->first < end) {
            seq_t  seq_match  = it->first;
            size_t size_match = it->second.size();
            seq_t  end_match  = seq_match + size_match;

            if (end_match <= end) {
                // The segment we placed contains all the data if this matching
                // segment, we erase it.

                it = tcb->out_of_order.erase(it);
                // TODO: free the erased segment.
            } else {
                // No more segment overlap. Stop.
                break;
            }

            it++;
        }
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
        net_t<seq_t> seq, net_t<seq_t> ack, mss_t mss
    )
    {
        options_t options = { (typename options_t::mss_option_t) mss };
        this->_send_segment(
            sport, daddr, dport, seq, ack, _SYN_ACK_FLAGS, 0, options
        );
    }

    void _send_ack_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        this->_send_segment(
            sport, daddr, dport, seq, ack, _ACK_FLAGS, 0, EMPTY_OPTIONS
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
            hdr->dport, saddr, hdr->sport,
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
        net_t<uint16_t> window, options_t options
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
            partial_sum_t options_sum;

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

    // Writes the TCP options starting at the given buffer cursor.
    //
    // Returns the cursor to write data after the options and the partial sum of
    // the options.
    static pair<cursor_t, partial_sum_t> _write_options(
        cursor_t cursor, options_t options
    )
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

    // -------------------------------------------------------------------------

    static inline seq_t _get_current_tcp_seq(void)
    {
        return network_t::data_link_t::phys_t::get_current_tcp_seq();
    }
};

//
// Initializes static fields
//

template <typename network_t>
const typename tcp_t<network_t>::options_t
tcp_t<network_t>::EMPTY_OPTIONS = {
    tcp_t<network_t>::options_t::NO_MSS_OPTION
};

// Initializes common flags

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
