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
#include <cstring>                  // equal_to, hash
#include <functional>               // equal_to, hash
#include <queue>
#include <tuple>
#include <unordered_map>

#include <netinet/tcp.h>            // TCPOPT_EOL, TCPOPT_NOP, TCPOPT_MAXSEG

#include "net/checksum.hpp"         // checksum(), partial_sum_t
#include "net/endian.hpp"           // net_t, to_host()

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
    typedef network_var_t                   network_t;

    typedef tcp_t<network_t>                this_t;

    typedef typename network_t::addr_t      addr_t;
    typedef uint16_t                        port_t;

    // Sequence number.
    typedef uint32_t                        seq_t;

    // Segment size.
    typedef uint16_t                        seg_size_t;

    // Maximum Segment Size
    typedef uint16_t                        mss_t;

    typedef uint16_t                        win_size_t;

    typedef typename network_t::cursor_t    cursor_t;

    // Uniquely identifies a TCP Control Block or a connection.
    typedef tcp_tcb_id_t<addr_t, port_t>    tcb_id_t;

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
            win_size_t  size;
            seq_t       next;   // Next sequence number expected to receive.
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
        struct tx_window_t {
            win_size_t  size;
            seq_t       unack;  // First byte sent but unacknowledged byte.
            seq_t       next;   // Next sequence number to send.
        } tx_window;

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

        mss_t                   mss;    // Maximum segment size (TCP segment
                                        // payload, without headers).
    };

    // Callback using in the call of 'accept()'.
    //
    // The function is given the identifier of the new established connection.
    typedef function<void(tcb_id_t)>    accept_callback_t;

    // Information about a port in LISTEN state.
    struct listen_t {
        // Functions to call when a new connection is established on the
        // listening port.
        //
        // The queue should be empty if 'pending_queue' is not empty.
        queue<accept_callback_t>    accept_queue;

        // Contains established connections which have not been handled by an
        // 'accept_callback_t'.
        //
        // The queue should be empty if 'accept_queue' is not empty and should
        // never exceed 'backlog'.
        queue<tcb_id_t>             pending_queue;

        // Maximum number of pending connections in 'pending_queue'.
        size_t                      backlog;
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
    };

    //
    // Static fields
    //

    static constexpr size_t                 HEADER_SIZE = sizeof (header_t);

    //
    // Fields
    //

    // Lower network layer instance.
    network_t                               *network;

    // Ports which are in the LISTEN state, passively waiting for client
    // connections.
    unordered_map<net_t<port_t>, listen_t>  listens;

    // TCP Control Blocks for active connections.
    unordered_map<tcb_id_t, tcb_t>          tcbs;

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

            #define IGNORE_SEGMENT(WHY, ...)                                   \
                do {                                                           \
                    TCP_ERROR(                                                 \
                        "Segment from %s:%" PRIu16 " ignored: " WHY,           \
                        network_t::addr_t::to_alpha(saddr), hdr->sport.host(), \
                        ##__VA_ARGS__                                          \
                    );                                                         \
                    return;                                                    \
                } while (0)

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

            #undef IGNORE_SEGMENT

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
                    this->_handle_syn_sent_state(saddr, hdr, payload, tcb);
                    break;
                case tcb_t::SYN_RECEIVED:
                    this->_handle_syn_received_state(hdr);
                    break;
                case tcb_t::ESTABLISHED:
                    this->_handle_established_state(hdr);
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

            TCP_DEBUG("MSS: %d", options.mss);
        });
    }

    //
    // Server sockets.
    //

    // Listen for TCP connections on the given port.
    //
    // Create a backlog of the given initial size to log
    listen_t listen(port_t port, size_t backlog)
    {
    }

    //
    // Client sockets.
    //

    

private:

    // -------------------------------------------------------------------------
    //
    // TCP state machine handlers.
    //
    // Each handler is responsible of the processing of a received segment with
    // the connection in the corresponding state.

    void _handle_listen_state(
        net_t<addr_t> saddr, const header_t *hdr, tcb_id_t tcb_id,
        options_t options, cursor_t payload, listen_t *listen
    )
    {
        static flags_t valid_syn_flags(0, 1 /* ack */, 0, 0, 0, 0);

        if (LIKELY(hdr->flags == valid_syn_flags && payload.is_empty())) {
            // Valid (expected) segment.
            if (!listen->accept_queue.empty()) {
                accept_callback_t callback = listen->accept_queue.front();
                listen->accept_queue.pop();

                this->_handle_listen_state_create_connection(
                    saddr, hdr, tcb_id, options
                );

                return callback(tcb_id);
            } else if (listen->pending_queue.size() < listen->backlog) {
                listen->pending_queue.push(tcb_id);

                return this->_handle_listen_state_create_connection(
                    saddr, hdr, tcb_id, options
                );
            } else {
                // There is no more room in the pending connection queue. The
                // connection in actually in the CLOSED state.
                return this->_handle_closed_state(saddr, hdr, payload);
            }
        } else
            // Invalid segment.
            return this->_respond_with_rst_segment(saddr, hdr, payload);
    }

    // Creates a TCB and responds to the received segment with a SYN-ACK
    // segment.
    void _handle_listen_state_create_connection(
        net_t<addr_t> saddr, const header_t *hdr, tcb_id_t tcb_id,
        options_t options
    )
    {
        // Creates an initializes the TCB.

        seq_t seq = _get_current_tcp_seq();

        auto p = this->tcbs.emplace(
            piecewise_construct, forward_as_tuple(tcb_id), forward_as_tuple()
        );
        assert(p.second); // Emplace succeed.
        tcb_t *tcb = &p.first->second;

        tcb->state      = tcb_t::SYN_RECEIVED;

        tcb->mss = this->network->max_payload_size - HEADER_SIZE;
        if (options.mss != options_t::NO_MSS_OPTION)
            tcb->mss = min(tcb->mss, (mss_t) options.mss);

        tcb->rx_window  = { tcb->mss, hdr->seq.host() + 1 };
        tcb->tx_window  = { hdr->window.host(), seq, seq + 1 };

        // Sends the SYN-ACK segment.

        this->_send_syn_ack_segment(
            hdr->dport, saddr, hdr->sport, seq, tcb->rx_window.next
        );
    }

    void _handle_syn_sent_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload, tcb_t *tcb
    )
    {
        if (UNLIKELY(hdr->flags.rst)) {
            // While in SYS-SENT, RST segments should be ignored if they don't
            // acknowledge the SYN segment we sent.
            if (hdr->ack == tcb->tx_window.unack)
                ;
//                 return this->_destroy_tcb(tcb);
        } else if (LIKELY(hdr->flags.syn)) {
            if (LIKELY(hdr->flags.ack)) {
                // We received a SYN-ACK segment. We must just check that the
                // segment acknowledges the SYN segment we sent.

                if (UNLIKELY(tcb->tx_window.unack != hdr->ack))
                    // Unexpected ACK number.
                    this->_respond_with_rst_segment(saddr, hdr, payload);
            } else {
                // We received a SYN segment without an ACK field. We move into
                // the SYN-RECEIVED state and acknowledge the segment.

                tcb->state = tcb_t::SYN_RECEIVED;
                tcb->rx_window.size = hdr->window.host();
                tcb->rx_window.next = hdr->seq.host() + 1;

                this->_send_ack_segment(
                    hdr->dport, saddr, hdr->sport,
                    tcb->tx_window.next, tcb->rx_window.next
                );
            }
        } else {
            // Invalid segment.
        }
    }

    void _handle_syn_received_state(const header_t *hdr)
    {
    }

    void _handle_established_state(const header_t *hdr)
    {
    }

    void _handle_fin_wait_1_state(const header_t *hdr)
    {
    }

    void _handle_fin_wait_2_state(const header_t *hdr)
    {
    }

    void _handle_close_wait_state(const header_t *hdr)
    {
    }

    void _handle_closing_state(const header_t *hdr)
    {
    }

    void _handle_last_ack_state(const header_t *hdr)
    {
    }

    void _handle_closed_state(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload
    )
    {
        this->_respond_with_rst_segment(saddr, hdr, payload);
    }

    // -------------------------------------------------------------------------
    //
    // TCB handling helpers
    //

    // Close a connection.
    void _destroy_tcb(tcb_id_t tcb_id, tcb_t tcb)
    {
    }

    // -------------------------------------------------------------------------
    //
    // Segment helpers
    //

    void _send_syn_ack_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        static flags_t flags(0, 1 /* ACK */, 0, 0, 1 /* SYN */, 0);

        this->_send_segment(
            sport, daddr, dport, seq, ack, flags, 0, cursor_t::EMPTY
        );
    }

    void _send_ack_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        static flags_t flags(0, 1 /* ACK */, 0, 0, 0, 0);

        this->_send_segment(
            sport, daddr, dport, seq, ack, flags, 0, cursor_t::EMPTY
        );
    }


    // Responds to a received segment with a RST segment.
    void _respond_with_rst_segment(
        net_t<addr_t> saddr, const header_t *hdr, cursor_t payload
    )
    {
        // The SEQ and ACK number are computed according to the SEQ and ACK
        // number of the received segment so the remote TCP can identify the
        // erroneous segment.

        net_t<seq_t> seq;
        if (hdr->flags.ack)
            seq = hdr->ack;
        else
            seq.net = 0;

        // SYN and FIN flags must be acknowledged and thus "consume" one byte.
        net_t<seq_t> ack = hdr->seq + hdr->flags.syn + hdr->flags.fin
                                    + payload.size();

        this->_send_rst_segment(hdr->dport, saddr, hdr->sport, seq, ack);
    }

    void _send_rst_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        static flags_t flags(0, 1 /* ACK */, 0, 1 /* RST */, 0, 0);

        this->_send_segment(
            sport, daddr, dport, seq, ack, flags, 0, cursor_t::EMPTY
        );
    }

    // Pushs the given segment with its payload to the network layer.
    void _send_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<uint16_t> window, cursor_t payload
    )
    {
        net_t<addr_t> saddr = this->network->addr;
        size_t seg_size = HEADER_SIZE + payload.size();

        // Precomputes the sum of the pseudo header and of the payload.
        partial_sum_t partial_sum =
            network_t::tcp_pseudo_header_sum(
                saddr, daddr, net_t<seg_size_t>(seg_size)
            ).append(partial_sum_t(payload));

        this->network->send_tcp_payload(
        daddr, seg_size,
        [sport, daddr, dport, seq, ack, flags, window, partial_sum]
        (cursor_t cursor) {
            _write_header(
                cursor, sport, dport, seq, ack, flags, window, partial_sum
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
            hdr->check   = checksum_t();
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
                    if (UNLIKELY(data + length > end)) {
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

    // Writes the Maximum Segment Size option starting at the given buffer
    // cursor.
    static cursor_t _write_mss_option(cursor_t cursor, mss_t mss)
    {
        
    }

    // -------------------------------------------------------------------------

    static inline seq_t _get_current_tcp_seq(void)
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
