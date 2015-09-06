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

#ifndef __RUSTY_NET_TCP_HPP__
#define __RUSTY_NET_TCP_HPP__

#include <algorithm>                // min()
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>               // equal_to, hash
#include <map>
#include <memory>                   // shared_ptr
#include <tuple>
#include <unordered_map>
#include <utility>                  // pair, swap()

#include <netinet/tcp.h>            // TCPOPT_EOL, TCPOPT_NOP, TCPOPT_MAXSEG

#include "net/checksum.hpp"         // checksum(), partial_sum_t
#include "net/endian.hpp"           // net_t, to_host()
#include "util/macros.hpp"          // LIKELY(), UNLIKELY()

using namespace std;

namespace rusty {
namespace net {

#define TCP_COLOR     COLOR_MAG
#define TCP_DEBUG(MSG, ...)                                                    \
    RUSTY_DEBUG("TCP", TCP_COLOR, MSG, ##__VA_ARGS__)
#define TCP_ERROR(MSG, ...)                                                    \
    RUSTY_ERROR("TCP", TCP_COLOR, MSG, ##__VA_ARGS__)

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
template <typename network_var_t, typename alloc_t = allocator<char *>>
struct tcp_t {
    //
    // Member types
    //

    // Redefines 'network_var_t' as 'network_t' so it can be accessible as a
    // member type.
    typedef network_var_t                           network_t;

    typedef typename network_t::clock_t             clock_t;
    typedef typename network_t::cursor_t            cursor_t;
    typedef typename network_t::timer_manager_t     timer_manager_t;
    typedef typename timer_manager_t::timer_id_t    timer_id_t;

    typedef tcp_t<network_t, alloc_t>               this_t;

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
            return ((int32_t) (a - b).value) < 0;
        }

        friend inline bool operator<=(seq_t a, seq_t b)
        {
            return ((int32_t) (a - b).value) <= 0;
        }

        friend inline bool operator>(seq_t a, seq_t b)
        {
            return ((int32_t) (a - b).value) > 0;
        }

        friend inline bool operator>=(seq_t a, seq_t b)
        {
            return ((int32_t) (a - b).value) >= 0;
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

    // Uniquely identifies a TCP Control Block.
    typedef tcp_tcb_id_t<addr_t, port_t>                tcb_id_t;

    // Function given to 'conn_t::send()' which writes data into a transmission
    // buffer.
    //
    // The first function argument gives the data offset at which the
    // transmission buffer starts.
    //
    // The number of bytes to write is given by the cursor size. The function
    // could be called an undefined number of times, with different offsets,
    // because of packet segmentation and retransmission.
    typedef function<void(size_t, cursor_t)>            writer_t;

    // Same as 'writer_t' but also returns the partial checksum of the written
    // data.
    typedef function<partial_sum_t(size_t, cursor_t)>   writer_sum_t;

    // Callback given to 'send()' which will be called once all the data
    // provided by the writer has been acked by the remote.
    typedef function<void()>                            acked_callback_t;

    // Datatype used by the application layer to control the connection.
    struct conn_t {
        tcp_t       *tcp_instance;
        tcb_id_t    tcb_id;

        // Returns 'true' if the the connection is in a state where data can be
        // sent using 'send()' (i.e. the 'close()' method has not been called
        // for this connection).
        inline bool can_send(void)
        {
            return tcp_instance->_can_send(tcb_id);
        }

        // Sends data to the remote TCP instance.
        //
        // The user must provides two function, one which will be called to
        // write the data into the network buffers, and one which will be called
        // once the data have been acknowledged by the remote TCP.
        inline void send(size_t length, writer_t writer, acked_callback_t acked)
        {
            tcp_instance->_send(tcb_id, length, writer, acked);
        }

        // Same as the previous 'send()' but uses a writer which also computes
        // the partial checksum of the written data.
        inline void send(
            size_t length, writer_sum_t writer, acked_callback_t acked
        )
        {
            tcp_instance->_send(tcb_id, length, writer, acked);
        }

        // Closes the TCP connection.
        //
        // Once called, no more data could be sent to the remote TCP using
        // 'send()'. However, data could still be received up until the
        // 'conn_handlers_t::remote_close()' event have been triggered.
        inline void close(void)
        {
            tcp_instance->_close(tcb_id);
        }
    };

    // Set of functions provided by the application layer to handle events of
    // a connection.
    struct conn_handlers_t {
        // Called when the connection receives new data.
        function<void(cursor_t)>                new_data;

        // Called when the remote asked to close the connection.
        //
        // The application layer can still send new data using 'send()' but no
        // new data will ever be received.
        function<void()>                        remote_close;

        // Called when both ends closed the connection. Resources allocated for
        // the connection should be released.
        //
        // No more data can be received nor sent.
        function<void()>                        close;

        // The connection has been unexpectedly closed (connection reset).
        // Resources allocated for the connection should be released.
        //
        // No more data can be received nor sent.
        function<void()>                        reset;
    };

    // Callback called on new connections on a port open in the LISTEN state.
    //
    // The function is given the identifier of the new established connection.
    typedef function<conn_handlers_t(conn_t)>           new_conn_callback_t;

    // Types related to the 'listens' hash table.
    typedef pair<const net_t<port_t>, new_conn_callback_t>
                                                        listens_pair_t;
    typedef typename alloc_t::template rebind<listens_pair_t>::other
                                                        listens_alloc_t;
    typedef unordered_map<
                net_t<port_t>, new_conn_callback_t,
                hash<net_t<port_t>>, equal_to<net_t<port_t>>,
                listens_alloc_t
            >                                           listens_t;

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
            // Moves in this state when the application layer decide to close
            // the connection.
            //
            // No more data could be asked to be transmitted by the application
            // layer. A FIN segment will be sent once the transmission queue
            // will be emptied and the connection will move into the FIN-WAIT-2
            // state once we receive an acknowledgement for it from the remote.
            FIN_WAIT_1   = 1 << 3,
            // The remote has acknowledged out FIN segment. The connection is
            // half-closed and we are listening for data or a connection
            // termination request from the remote TCP.
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
            seq_t       acked;  // Last acknowledgement number for which a
                                // segment has been sent. Could be lesser than
                                // 'next'.

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
            win_size_t  rwnd;   // Receiver window size.
            seq_t       wl1;    // Received sequence number of the last segment
                                // used to update 'rwnd'.
            seq_t       wl2;    // Received acknowledgment number of the last
                                // segment used to update 'rwnd'.
            win_size_t  cwnd;   // Congestion window size.

            // Slow Start threshold.
            //
            // The Slow Start algorithm is used when 'cwnd' < 'ssthresh'.
            // The Congestion Avoidance algorithm is used otherwise.
            //
            // RFC 5681 page 5 specifies that 'ssthresh' should be set to an
            // arbitrary high value.
            win_size_t  ssthresh = UINT16_MAX;

            // Effective size of the window.
            //
            // When duplicates segments are received, the congestion window is
            // virtually inflated so TCP still emits segments.
            //
            // Always equals to 'min(rwnd, cwnd + dupacks * mss)'.
            win_size_t  size;

            seq_t       unack;  // First sent but unacknowledged byte.
            seq_t       next;   // Next sequence number to send.
            mss_t       mss;    // Sender Maximum Segment Size (TCP segment
                                // payload, without headers).
                                //
                                // This is the value is the minimum of the
                                // received MSS option and the MSS allowed by
                                // the driver.

            // Currently received duplicate ACKs segments.
            int         dupacks = 0;

            // Initializes 'rwnd', 'wl1', 'wl2', 'cwnd', 'size' and 'mss' from a
            // received SYN segment (with 'irs' being the Initial Received
            // Sequence number).
            //
            // 'unack' and 'next' should already been set.
            void init_from_syn(
                const tcp_t *tcp, const header_t *hdr, seq_t irs,
                options_t options
            )
            {
                rwnd  = hdr->window.host();
                wl1   = irs;
                wl2   = unack;

                // RFC 5681 specifies that if no MSS option is used, the remote
                // MSS is assumed to be equal to 536.
                mss   =   options.mss != options_t::NO_MSS_OPTION
                        ? options.mss : (mss_t) 536;

                // Limits the MSS value to the maximum segment size that the
                // driver can send.
                mss  = min(mss, tcp->mss);

                this->reset_cwnd();
            }

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

            // Returns the first sequence number that is outside of the window.
            inline seq_t end(void) const
            {
                return unack + (seq_t) size;
            }

            // Returns the number of bytes sequence numbers that are ready to
            // be used.
            inline size_t ready(void) const
            {
                return (end() - next).value;
            }

            // Returns the amount of bytes that has been sent but not yet
            // acknowledged
            inline size_t in_flight(void) const
            {
                return (next - unack).value;
            }

            // Returns 'true' if there is at least one sequence number ready to
            // be used.
            inline bool can_transmit(void) const
            {
                return next < end();
            }

            // Updates the remote window size and the values of 'wl1' and 'wl2'
            // if 'wl1 < seq || (wl1 == seq && wl2 <= ack)' (this prevents old
            // segments to update the window).
            //
            // Returns 'true' if the window has been updated.
            bool update_rwnd(
                seq_t seq, seq_t ack, win_size_t received_size
            )
            {
                if (wl1 < seq || (wl1 == seq && wl2 <= ack)) {
                    rwnd = received_size;
                    _update_size();
                    wl1  = seq;
                    wl2  = ack;

                    return true;
                } else
                    return false;
            }

            // Returns 'true' if the transmission window is currently in the
            // slow start congestion control algorithm.
            //
            // RFC 5681 states that the slow start algorithm should be used when
            // 'cwnd' < 'ssthresh'.
            inline bool in_slow_start(void) const
            {
                return cwnd < ssthresh;
            }

            // Resets the congestion window to its initial value.
            //
            // This usually occurs when the retransmission timer is trigerred
            // and that the connection must use the slow start algorithm again.
            void reset_cwnd(void)
            {
                // RFC 5681 page 5 tells TCP implementations to use the
                // following initial congestion window values as upper bound.
                if (mss <= 1095)
                    cwnd = 4 * mss;
                else if (mss <= 2190)
                    cwnd = 3 * mss;
                else
                    cwnd = 2 * mss;

                _update_size();
            }

            void update_cwnd(size_t bytes_acked)
            {
                if (in_slow_start()) {
                    // Increases the congestion window by the number of bytes
                    // acked, as stated in RFC 5681 page 6.
                    cwnd += min(bytes_acked, (size_t) mss);
                } else { // In congestion avoidance.
                    // Increases the congestion window by one sender MSS per RTT
                    // using the approximation equation specified in RFC 5681
                    // page 7.
                    cwnd += max(
                        size_t(1), ((size_t) mss * (size_t) mss) / cwnd
                    );
                }

                _update_size();
            }

            // Updates the window size (by mutating the 'dupacks', 'cwnd' and
            // 'size' field to account the reception of a duplicate ack.
            void receive_duplicate_ack(void)
            {
                ++dupacks;

                if (dupacks == 3) {
                    // We received a third duplicate ACK.
                    //
                    // We must set 'ssthresh' using the equation at RFC 5681
                    // page 7 and updates the congestion window as specified on
                    // page 9.

                    cwnd = ssthresh = max(in_flight() / 2, (size_t) (2 * mss));
                }

                _update_size();
            }

        private:
            // Recomputes 'size' from 'rwnd', 'cwnd' and 'dupacks'.
            inline void _update_size(void)
            {
                size = min(rwnd, (win_size_t) (cwnd + dupacks * mss));
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

        // Contains segment payloads which have not been delivered to the
        // application layer nor acknowledged because they have been delivered
        // out of order.
        vector<out_of_order_segment_t, alloc_t>         out_of_order;

        //
        // Transmission queues
        //
        // The queues contain entries which have already been sent but
        // unacknowledged ('tx_queue_sent_unack') and entries that are waiting
        // to be sent ('tx_queue_not_sent').
        //
        // The queues are composed of functions instead of buffer. These
        // functions (named "writers")  are able to write a determined amount of
        // bytes in network buffers.
        // Both queue entries are sorted in increasing sequence number order.
        //
        // The sequence number of an entry ('seq') directly follows the last
        // sequence number of the preceding entry ('seq' of the N-th entry is
        // equal to 'seq + size' of the N-1-th entry).

        // A queue entry contains a function able to write data from 'begin'
        // (included) to 'end' (excluded). The 'acked' function is called once
        // the whole entry has been transmitted and acknowledged.
        struct tx_queue_entry_t {
            seq_t                               begin;
            seq_t                               end;

            // Function provided by the user to write data into transmission
            // buffers.
            writer_sum_t                        writer;

            // Function which is called once all the data provided by the writer
            // has been acked by the remote.
            acked_callback_t                    acked;
        };

        // Contains entries which have been entirely sent but which have not
        // been entirely acknowledged yet.
        //
        // Entries will be removed once they have been fully acknowledged.
        deque<tx_queue_entry_t, alloc_t>        tx_queue_sent_unack;

        // Contains entries which are pending to be sent.
        //
        // The first entry of this queue may be partially sent. Once an entry
        // has been fully transmitted, it is moved into the
        // 'tx_queue_sent_unack' queue.
        deque<tx_queue_entry_t, alloc_t>        tx_queue_not_sent;

        // History entry of a transmitted segments.
        //
        // Used to estimate the Round Trip Time and to recover from 
        // loss.
        struct tx_history_entry_t {
            seq_t                       end;        // First sequence number
                                                    // after the segment.
            typename clock_t::time_t    tx_time;    // Transmission time.

            // 'true' if retransmitted. Retransmitted segment should be ignored
            // when estimating the Round Trip Time.
            bool                        retransmitted = false;

            tx_history_entry_t(seq_t _end)
                : end(_end), tx_time(clock_t::time_t::now())
            {
            }
        };

        // History of unacknowledged segments. Entries are kept sorted in
        // ascending order.
        deque<tx_history_entry_t, alloc_t>  tx_history;

        // Data used by TCP to compute the Retransmission Time Out (RTO) by
        // estimating the round trip time to the remote TCP.
        struct rtt_t {
            // Factor stated by RFC 6298 page 3.
            static constexpr double ALPHA   = 1 / 8;
            static constexpr double BETA    = 1 / 4;

            // Retranmission TimeOut. Based on the RTT.
            typename clock_t::interval_t        rto;

            // Variables used to compute RTO as described in RFC 6298.
            typename clock_t::interval_t        srtt;   // Average RTT.
            typename clock_t::interval_t        rttvar; // Standard deviation.

            // Is 'true' when no RTT have already been observed.
            bool                                first = true;

            // RFC 6298 tells that the RTO should be set to one second before
            // any measurement has been done.
            rtt_t(void) : rto(1000000L)
            {
            }

            // Updates the estimated RTT using the observed RTT of the incoming
            // acknowledgment segment and the transmission history.
            //
            // Uses the method in RFC 6298 page 3.
            void update_rtt(tcb_t *tcb, seq_t ack)
            {
                typename clock_t::time_t now = clock_t::time_t::now();

                while (!tcb->tx_history.empty()) {
                    const tx_history_entry_t *entry = &tcb->tx_history.front();

                    if (entry->end > ack)
                        break;

                    // Measured RTT.
                    typename clock_t::interval_t rtt = now - entry->tx_time;

                    tcb->tx_history.pop_front();

                    if (!entry->retransmitted)
                        continue;

                    if (first) {
                        // First measurement.
                        srtt    = rtt;
                        rttvar  = rtt * 0.5;
                        first   = false;
                    } else {
                        // Subsequent measurements.
                        rttvar  = rttvar * (1 - BETA) + (srtt - rtt) * BETA;
                        srtt    = srtt * (1 - ALPHA) + rtt * ALPHA;
                    }

                    // RTO can not be less than one second.
                    static const typename clock_t::interval_t ONE_SEC(1000000);
                    rto = min(ONE_SEC, srtt + rttvar * 4);
                }
            }
        } rtt;

        // Current timer identifier.
        //
        // If in an established state, references the retransmission timer.
        // If in the TIME-WAIT state, references the 2MSL timer.
        // If 'has_timer' is false, contains an undefined value.
        timer_id_t                              timer;
        bool                                    has_timer;

        // Functions provided by the application layer to manage connection
        // events.
        conn_handlers_t                         conn_handlers;

        tcb_t(alloc_t _alloc = alloc_t())
            : out_of_order(_alloc), tx_queue_sent_unack(_alloc),
              tx_queue_not_sent(_alloc), tx_history(_alloc)
        {
        }

        inline bool in_state(state_t states) const
        {
            return this->state & states;
        }

        // Updates the tranmission queue with the received ack segment.
        void update_tx_queues(seq_t ack)
        {
            // Removes transmission queue entries which have been acknowledged.
            while (!tx_queue_sent_unack.empty()) {
                const auto *entry = &tx_queue_sent_unack.front();

                if (entry->end <= ack) {
                    entry->acked();
                    tx_queue_sent_unack.pop_front();
                } else
                    break;
            }
        }
    };

    // Types related to the 'tcbs' hash table.
    typedef pair<const tcb_id_t, tcb_t>                 tcbs_pair_t;
    typedef typename alloc_t::template rebind<tcbs_pair_t>::other
                                                        tcbs_alloc_t;
    typedef unordered_map<
                tcb_id_t, tcb_t,
                hash<tcb_id_t>, equal_to<tcb_id_t>,
                tcbs_alloc_t
            >                                           tcbs_t;
    //
    // Static fields
    //

    static constexpr size_t                     HEADER_SIZE = sizeof (header_t);

    static const     options_t                  EMPTY_OPTIONS;

    // Initial size of the receiver (local) window in bytes.
    //
    // 29,200 bytes is the default value on Linux with 10 Gbps links.
    static constexpr win_size_t                 INITIAL_WND_SIZE = 29200;

    // Delay in which a connection stays in the TIME-WAIT state before being
    // removed ("2MSL" timeout).
    static const typename clock_t::interval_t   FIN_TIMEOUT;

    // Maximum number of out of order segments which will be retained before
    // starting to drop them.
    //
    // NOTE: current implementation is not efficient (quadradic against the
    // number of out of order segments), but shouldn't be an issue as storing a
    // large a number of out of order segments is not appealing (Linux use 3 as
    // default value).
    static constexpr size_t                     MAX_OUT_OF_ORDER_SEGS = 3;

    //
    // Fields
    //

    // Lower network layer instance.
    network_t       *network;

    timer_manager_t *timers;

    alloc_t         alloc;

    // Ports which are in the LISTEN state, passively waiting for client
    // connections.
    //
    // Each open port maps to a callback function provided by the application to
    // handle new connections.
    listens_t       listens;

    // TCP Control Blocks for active connections.
    tcbs_t          tcbs;

    // Maximum segment size (TCP segment payload, without headers but with
    // options) that this TCP instance can emit.
    mss_t           mss;

    //
    // Methods
    //

    // Creates an TCP environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    tcp_t(alloc_t _alloc = alloc_t())
      : alloc(_alloc),
        listens(0, hash<net_t<port_t>>(), equal_to<net_t<port_t>>(), _alloc),
        tcbs(0, hash<tcb_id_t>(), equal_to<tcb_id_t>(), _alloc)
    {
    }

    // Creates a TCP environment for the given network layer instance.
    //
    // Does the same thing as creating the environment with 'tcp_t()' and then
    // calling 'init()'.
    tcp_t(
        network_t *_network, timer_manager_t *_timers,
        alloc_t _alloc = alloc_t()
    ) : network(_network), timers(_timers), alloc(_alloc),
        listens(0, hash<net_t<port_t>>(), equal_to<net_t<port_t>>(), _alloc),
        tcbs(0, hash<tcb_id_t>(), equal_to<tcb_t>(), _alloc),
        mss(_network->max_payload_size - HEADER_SIZE)
    {
    }

    // Initializes a TCP environment for the given network layer instance.
    void init(network_t *_network, timer_manager_t *_timers)
    {
        network = _network;
        timers  = _timers;
        mss     = _network->max_payload_size - HEADER_SIZE;
    }

    #define IGNORE_SEGMENT(WHY, ...)                                           \
        do {                                                                   \
            TCP_ERROR(                                                         \
                "Segment from %s:%" PRIu16 " ignored: " WHY,                   \
                network_t::addr_t::to_alpha(tcb_id.raddr),                     \
                tcb_id.rport.host(), ##__VA_ARGS__                             \
            );                                                                 \
            return;                                                            \
        } while (0)

    #define TCP_TCB_DEBUG(MSG, ...)                                            \
        do {                                                                   \
            TCP_DEBUG(                                                         \
                "%s:%" PRIu16 " on local port %" PRIu16 ": " MSG,              \
                network_t::addr_t::to_alpha(tcb_id.raddr), tcb_id.rport.host(),\
                tcb_id.lport.host(), ##__VA_ARGS__                             \
            );                                                                 \
        } while (0)

    #define TCP_TCB_ERROR(MSG, ...)                                            \
        do {                                                                   \
            TCP_ERROR(                                                         \
                "%s:%" PRIu16 " on local port %" PRIu16 ": " MSG,              \
                network_t::addr_t::to_alpha(tcb_id.raddr), tcb_id.rport.host(),\
                tcb_id.lport.host(), ##__VA_ARGS__                             \
            );                                                                 \
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
            tcb_id_t tcb_id = { saddr, hdr->sport, hdr->dport };

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

            // Processes the segment with the handler corresponding to the
            // current state of the TCP connection.
            //
            // The two LISTEN and CLOSED states are handled separatly as there
            // is no TCB for them.

            TCP_TCB_DEBUG("Segment received");

            auto tcb_it = this->tcbs.find(tcb_id);

            if (tcb_it == this->tcbs.end()) {
                // No existing TCB for the connection.

                auto listen_it = this->listens.find(hdr->dport);

                if (LIKELY(listen_it != this->listens.end())) {
                    this->_handle_listen_state(
                        hdr, tcb_id, options, payload, &listen_it->second
                    );
                } else
                    this->_handle_closed_state(saddr, hdr, payload);
            } else {
                tcb_t *tcb = &tcb_it->second;

                if (tcb->in_state(tcb_t::SYN_SENT)) {
                    this->_handle_syn_sent_state(
                        hdr, options, payload, tcb_id, tcb
                    );
                } else
                    this->_handle_other_states(hdr, payload, tcb_id, tcb);
            }
        });
    }

    #define TCP_TCB_STATE_CHANGE(FROM, TO)                                     \
        TCP_TCB_DEBUG("State changed (" FROM " -> " TO ")");

    //
    // Server sockets.
    //

    // Starts listening for TCP connections on the given port.
    //
    // If the port was already in the listen state, replaces the previous
    // callback function.
    void listen(port_t port, new_conn_callback_t new_conn_callback)
    {
        assert(this->listens.find(port) == this->listens.end());

        this->listens.emplace(port, new_conn_callback);

        TCP_DEBUG(
            "State change for local port %" PRIu16 ": from CLOSED to LISTEN",
            port
        );
    }

private:

    // Vector type used in the call to '_send_data_segment()'.
    typedef vector<typename tcb_t::tx_queue_entry_t, alloc_t>   to_send_vec_t;

    //
    // Connected sockets.
    //
    // These methods are called by 'conn_t' methods.
    //

    // Returns 'true' if the the connection is in a state where data can be
    // sent using 'send()' (i.e. the 'close()' method has not been called
    // for this connection).
    inline bool _can_send(tcb_id_t tcb_id)
    {
        auto tcb_it = this->tcbs.find(tcb_id);
        assert(tcb_it != this->tcbs.end());

        tcb_t *tcb = &tcb_it->second;

        return tcb->in_state(
            tcb_t::SYN_RECEIVED | tcb_t::SYN_SENT | tcb_t::ESTABLISHED |
            tcb_t::CLOSE_WAIT
        );
    }

    // Sends data to the remote TCP instance.
    //
    // See 'conn_t::send()'.
    void _send(
        tcb_id_t tcb_id, size_t length, writer_t writer,
        acked_callback_t acked_callback
    )
    {
        writer_sum_t writer_sum =
            [writer](size_t size, cursor_t out)
            {
                writer(size, out);
                return partial_sum_t(out);
            };

        this->_send(tcb_id, length, writer_sum, acked_callback);
    }

    // Same as the previous 'send()' but uses a writer which also computes the
    // partial checksum of the written data.
    //
    // See 'conn_t::send()'.
    void _send(
        tcb_id_t tcb_id, size_t length, writer_sum_t writer,
        acked_callback_t acked_callback
    )
    {
        // The connection has not been already closed by the application layer.
        assert(this->_can_send(tcb_id));

        auto tcb_it = this->tcbs.find(tcb_id);
        assert(tcb_it != this->tcbs.end());

        tcb_t *tcb = &tcb_it->second;

        if (length <= 0)
            return;

        // First sequence number that is outside of the transmission window.
        seq_t end_of_win = tcb->tx_window.end();

        typename tcb_t::tx_queue_entry_t entry;
        entry.writer = writer;
        entry.acked  = acked_callback;

        if (
               tcb->in_state(tcb_t::SYN_RECEIVED | tcb_t::SYN_SENT)
            || end_of_win <= tcb->tx_window.next
        ) {
            // If not in a transmitting state, or if the transmission window has
            // no free sequence number, just en-queues the transmission of the
            // data.

            if (tcb->tx_queue_not_sent.empty())
                entry.begin = tcb->tx_window.next;
            else
                entry.begin = tcb->tx_queue_not_sent.back().end;

            entry.end = entry.begin + seq_t(length);
            tcb->tx_queue_not_sent.push_back(entry);
        } else {
            // Transmits some data immediately.

            assert(tcb->tx_queue_not_sent.empty());
            assert(end_of_win > tcb->tx_window.next);

            entry.begin = tcb->tx_window.next;
            entry.end = entry.begin + seq_t(length);

            if (end_of_win >= entry.end) {
                // All the data can be delivered immediately.

                tcb->tx_queue_sent_unack.push_back(entry);
            } else {
                // Some part of the data can't be delivered immediately.

                tcb->tx_queue_not_sent.push_back(entry);
            }

            // First sequence number which is outside of the transmission window
            // or not in the data to transmit.
            seq_t end_of_transmission = min(end_of_win, entry.end);

            // Divides the data in TCP segments.
            do {
                // First sequence number that can't be send in this segment.
                seq_t end_of_seg = min(
                    end_of_transmission,
                    tcb->tx_window.next + (seq_t) tcb->tx_window.mss
                );

                size_t payload_size = (end_of_seg - tcb->tx_window.next).value,
                       offset       = (tcb->tx_window.next - entry.begin).value;

                assert(payload_size <= tcb->tx_window.mss);
                assert(payload_size <= tcb->tx_window.ready());

                function<partial_sum_t(cursor_t)> payload_writer =
                    [writer, offset](cursor_t cursor)
                    {
                        return writer(offset, cursor);
                    };

                TCP_TCB_DEBUG(
                    "Sends data segment "
                    "(<SEQ=%u><ACK=%u><CTL=ACK><%zu bytes payload>)",
                    tcb->tx_window.next.value, tcb->rx_window.next.value,
                    payload_size
                );

                this->_send_ack_segment(
                    tcb_id, tcb, tcb->tx_window.next, tcb->rx_window.next,
                    payload_writer, payload_size
                );

                // Updates the transmission windows.
                tcb->tx_window.next += (seq_t) payload_size;

                // Updates the transmission history.
                typename tcb_t::tx_history_entry_t segment(tcb->tx_window.next);
                tcb->tx_history.push_back(segment);
            } while (end_of_transmission > tcb->tx_window.next);

            tcb->rx_window.acked = tcb->rx_window.next;

            if (!tcb->has_timer)
                this->_schedule_retransmission_timer(tcb_id, tcb);
        }
    }

    // Closes the TCP connection.
    //
    // See 'conn_t::close()'.
    void _close(tcb_id_t tcb_id)
    {
        auto tcb_it = this->tcbs.find(tcb_id);
        assert(tcb_it != this->tcbs.end());

        tcb_t *tcb = &tcb_it->second;

        // The connection has already been closed by the application layer.
        if (tcb->in_state(
            tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2 | tcb_t::CLOSING |
            tcb_t::TIME_WAIT | tcb_t ::LAST_ACK
        ))
            return;

        if (tcb->in_state(tcb_t::SYN_SENT)) {
            tcb->conn_handlers.close();
            return this->_destroy_tcb(tcb_id);
        }

        if (tcb->tx_queue_not_sent.empty()) {
            // Sends a FIN segment immediately.

            TCP_TCB_DEBUG(
                "Sends FIN/ACK segment (<SEQ=%u><ACK=%u><CTL=FIN,ACK>)",
                tcb->tx_window.next.value, tcb->rx_window.next.value
            );

            this->_send_fin_ack_segment(
                tcb_id, tcb, tcb->tx_window.next, tcb->rx_window.next
            );

            tcb->rx_window.acked = tcb->rx_window.next;
            ++tcb->tx_window.next; // Transmitted FIN control bit.

            if (!tcb->has_timer)
                this->_schedule_retransmission_timer(tcb_id, tcb);
        } else
            assert(!tcb->tx_window.can_transmit());

        switch (tcb->state) {
        case tcb_t::SYN_RECEIVED:
            tcb->state = tcb_t::FIN_WAIT_1;
            TCP_TCB_STATE_CHANGE("SYN-RECEIVED", "FIN-WAIT-1");
            break;
        case tcb_t::ESTABLISHED:
            tcb->state = tcb_t::FIN_WAIT_1;
            TCP_TCB_STATE_CHANGE("ESTABLISHED", "FIN-WAIT-1");
            break;
        case tcb_t::CLOSE_WAIT:
            tcb->state = tcb_t::LAST_ACK;
            tcb->conn_handlers.close();
            break;
        default:
            break;
        };
    }

    // -------------------------------------------------------------------------

    // Common flags
    static const flags_t _SYN_FLAGS;        // <CTL=SYN>
    static const flags_t _SYN_ACK_FLAGS;    // <CTL=SYN,ACK>

    static const flags_t _FIN_ACK_FLAGS;    // <CTL=FIN,ACK>

    static const flags_t _ACK_FLAGS;        // <CTL=ACK>

    static const flags_t _RST_FLAGS;        // <CTL=RST>
    static const flags_t _RST_ACK_FLAGS;    // <CTL=RST,ACK>

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
        const header_t *hdr, tcb_id_t tcb_id, options_t options,
        cursor_t payload, const new_conn_callback_t *new_conn_callback
    )
    {
        if (UNLIKELY(hdr->flags.rst)) {
            // Ignore RST segments.
            IGNORE_SEGMENT("RST segment received while in LISTEN state");
        } else if (UNLIKELY(hdr->flags.ack)) {
            // There is nothing to be acknowledged in the LISTEN state.
            return this->_respond_with_rst_segment(tcb_id.raddr, hdr, payload);
        } else if (LIKELY(hdr->flags.syn)) {
            // SYN segment.
            //
            // Creates the TCB in the SYN-RECEIVED state and responds to the
            // segment with a SYN-ACK segment. Notifies the application of the
            // new connection.

            TCP_TCB_STATE_CHANGE("LISTEN", "SYN-RECEIVED");

            //
            // Creates an initializes the TCB.
            //

            seq_t irs = hdr->seq.host();        // Initial Receiver Sequence
                                                // number.
            seq_t iss = _get_current_tcp_seq(); // Initial Sender Sequence
                                                // number.

            auto p = this->tcbs.emplace(
                piecewise_construct, forward_as_tuple(tcb_id),
                forward_as_tuple(this->alloc)
            );
            assert(p.second); // Emplace succeed.
            tcb_t *tcb = &p.first->second;

            tcb->state = tcb_t::SYN_RECEIVED;

            tcb->rx_window.next = irs + seq_t(1);
            tcb->rx_window.size = INITIAL_WND_SIZE;
            tcb->rx_window.acked = tcb->rx_window.next;

            tcb->tx_window.unack = iss;
            tcb->tx_window.next  = iss + seq_t(1);
            tcb->tx_window.init_from_syn(this, hdr, irs, options);

            //
            // Sends the SYN-ACK segment.
            //

            this->_send_syn_ack_segment(tcb_id, tcb, iss, tcb->rx_window.next);

            this->_schedule_retransmission_timer(tcb_id, tcb);

            //
            // Notifies the application.
            //

            // Copies the callback before calling it as it could be removed
            // while being called.
            new_conn_callback_t callback = *new_conn_callback;
            conn_t conn = { this, tcb_id };
            conn_handlers_t conn_handlers = callback(conn);

            // As the new connection callback could have initiated a new
            // connection, and subsequently modified the 'tcbs' map, the 'tcb'
            // pointer is now potentially invalidated and must be reacquired
            // before assigning it the 'conn_handler'.

            auto tcb_it = this->tcbs.find(tcb_id);

            // The TCB should always exist, even if the callback decided to
            // close the connection, in which case it moved into the FIN-WAIT-1
            // state.
            assert(tcb_it != this->tcbs.end());

            tcb = &tcb_it->second;
            tcb->conn_handlers = conn_handlers;
        } else {
            // Any other segment is not valid and should be ignored.
            IGNORE_SEGMENT("invalid segment");
        }
    }

    //
    // SYN-SENT
    //

    void _handle_syn_sent_state(
        const header_t *hdr, options_t options, cursor_t payload,
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

                if (!hdr->flags.rst) {
                    return this->_respond_with_rst_segment(
                        tcb_id.raddr, hdr, payload
                    );
                }
            } else if (UNLIKELY(hdr->flags.rst))
                this->_reset_tcb(tcb_id, tcb);
            else if (LIKELY(hdr->flags.syn)) {
                // Moves into the ESTABLISHED state and acknowledges the
                // received SYN/ACK segment.

                TCP_TCB_STATE_CHANGE("SYN-SENT", "ESTABLISHED");

                tcb->state = tcb_t::ESTABLISHED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.next = irs + seq_t(1);

                tcb->tx_window.init_from_syn(this, hdr, irs, options);

                size_t payload_size = payload.size();
                if (payload_size > 0) {
                    this->_handle_in_order_payload(
                        irs + 1, payload, payload_size, tcb
                    );
                }

                // Acknowledges the received SYN segment and adds any pending
                // data.

                this->_respond_with_data_segments(tcb_id, tcb);

                if (tcb->rx_window.acked < tcb->rx_window.next)
                    this->_respond_with_ack_segment(tcb_id, tcb);
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

                TCP_TCB_STATE_CHANGE("SYN-SENT", "SYN-RECEIVED");

                tcb->state = tcb_t::SYN_RECEIVED;

                seq_t irs = hdr->seq.host(); // Initial Receiver Sequence
                                             // number.

                tcb->rx_window.next = irs + 1;

                tcb->tx_window.init_from_syn(this, hdr, irs, options);

                return this->_respond_with_ack_segment(tcb_id, tcb);
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
    // SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT,
    // CLOSING, LAST-ACK
    //

    void _handle_other_states(
        const header_t *hdr, cursor_t payload, tcb_id_t tcb_id, tcb_t *tcb
    )
    {
        // Implemented as specified in RFC 793 page 69 to 76.

        seq_t seq = hdr->seq.host();

        // Checks that the segment contains data which is in the receiving
        // window.
        if (UNLIKELY(!tcb->rx_window.acceptable_seg(seq, payload.size()))) {
            // Old duplicate.

            if (!hdr->flags.rst)
                this->_respond_with_ack_segment(tcb_id, tcb);

            IGNORE_SEGMENT("unexpected sequence number (duplicate ?)");
        }

        if (UNLIKELY(hdr->flags.rst))
            return this->_reset_tcb(tcb_id, tcb);

        if (UNLIKELY(hdr->flags.syn)) {
            // Only invalid SYN segment should reach this stage, as any
            // duplicate of the initial SYN segment should have been dropped
            // earlier.

            this->_reset_tcb(tcb_id, tcb);

            return this->_respond_with_rst_segment(tcb_id.raddr, hdr, payload);
        }

        if (UNLIKELY(!hdr->flags.ack)) {
            // Any segment in these states should have the ACK control bit set
            // as required by RFC 793 (page 72).
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

                TCP_TCB_STATE_CHANGE("SYN-RECEIVED", "ESTABLISHED");
                tcb->state = tcb_t::ESTABLISHED;
            } else {
                return this->_respond_with_rst_segment(
                    tcb_id.raddr, hdr, payload
                );
            }
        }

        // Could not be in the SYN-RECEIVED state anymore.
        assert(!tcb->in_state(tcb_t::SYN_RECEIVED));

        // Updates the transmission window according to the received ACK number.
        if (tcb->in_state(
            tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2 |
            tcb_t::CLOSE_WAIT | tcb_t::CLOSING | tcb_t::LAST_ACK
        )) {
            if (LIKELY(acceptable_ack)) {
                // The segment acknowledges something new.

                size_t bytes_acked = (ack - tcb->tx_window.unack).value;
                assert(bytes_acked > 0);

                tcb->tx_window.unack = ack;

                // Cancels any duplicate ACKs that have been received.
                tcb->tx_window.dupacks = 0;

                tcb->tx_window.update_rwnd(seq, ack, hdr->window.host());
                tcb->tx_window.update_cwnd(bytes_acked);

                tcb->rtt.update_rtt(tcb, ack);

                tcb->update_tx_queues(ack);

                if (tcb->tx_window.in_flight() > 0) {
                    // There is some pending data.
                    // Restarts the the retransmission timer.
                    this->_reschedule_retransmission_timer(tcb);
                } else {
                    // Unschedules the retransmission timer as everything has
                    // been acknowledged.
                    this->_unschedule_timer(tcb);
                }
            } else if (ack > tcb->tx_window.next) {
                // Acknowledgement of something not yet send.
                return this->_respond_with_ack_segment(tcb_id, tcb);
            } else if (ack == tcb->tx_window.unack) {
                // The segment does not acknowledge something new. It could be a
                // duplicate ACK if:
                // - it does not announce a new remote receiver windows size.
                // - it does not carry any data.
                // - it does not have a FIN control bit.
                // - we sent something that has not been acknowledged yet.
                //
                // See RFC 5681, page 44.

                bool updated = tcb->tx_window.update_rwnd(
                    seq, ack, hdr->window.host()
                );

                if (
                       !updated && payload.empty() && !hdr->flags.fin
                    && tcb->tx_window.in_flight() > 0
                ) {
                    tcb->tx_window.receive_duplicate_ack();

                    if (tcb->tx_window.dupacks == 3) {
                        TCP_TCB_ERROR("Third duplicate ack");

                        // Restarts the retransmission timer.
                        this->_reschedule_timer(tcb, tcb->rtt.rto);

                        this->_retransmit(tcb_id, tcb);
                    }
                }
            }

            // When in the FIN-WAIT-1 state, if the FIN has been sent and if it
            // is now acknowledged, enters the FIN-WAIT-2 state.
            if (
                   tcb->in_state(tcb_t::FIN_WAIT_1)
                && ack == tcb->tx_window.next
                && tcb->tx_queue_not_sent.empty()
            ) {
                TCP_TCB_STATE_CHANGE("FIN-WAIT-1", "FIN-WAIT-2");
                tcb->state = tcb_t::FIN_WAIT_2;
            }

            // When in the CLOSING state, if the FIN is acknowledged, enters
            // the TIME-WAIT state, otherwise, stop processing the segment.
            if (tcb->in_state(tcb_t::CLOSING)) {
                if (ack == tcb->tx_window.next) {
                    TCP_TCB_STATE_CHANGE("CLOSING", "TIME-WAIT");
                    tcb->state = tcb_t::TIME_WAIT;
                    this->_schedule_fin_timeout(tcb_id, tcb);
                } else
                    return;
            }
        } else if (
               tcb->in_state(tcb_t::LAST_ACK)
            && ack == tcb->tx_window.next
            && tcb->tx_queue_not_sent.empty()
        ) {
            // When in the LAST-ACK state, if our FIN is now acknowledged,
            // delete the TCB and return.
            return this->_destroy_tcb(tcb_id, tcb);
        }

        // Could not be in the CLOSING state anymore.
        assert(!tcb->in_state(tcb_t::CLOSING));

        // TODO: processes URG segments.

        //
        // Processes the segment text and updates the reception window.
        //

        if (
            tcb->in_state(
                tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2
            ) && !payload.empty()
        )
            this->_handle_payload(seq, payload, tcb);

        //
        // Processes the FIN control bit and acknowledges the received segment.
        //

        if (hdr->flags.fin) {
            switch (tcb->state) {
            case tcb_t::ESTABLISHED:
                ++tcb->rx_window.next;

                TCP_TCB_STATE_CHANGE("ESTABLISHED", "CLOSE-WAIT");
                tcb->state = tcb_t::CLOSE_WAIT;

                tcb->conn_handlers.remote_close();
                break;
            case tcb_t::FIN_WAIT_1:
                ++tcb->rx_window.next;

                // We would already be in the FIN-WAIT-2 if our FIN was acked,
                // because of the previous ACK processing.

                if (tcb->tx_queue_not_sent.empty()) {
                    // The only way to reach this stage is by not having
                    // received an acknowledgment for the FIN segment we sent,
                    // otherwise we would already be in the FIN-WAIT-2 state.

                    assert(ack < tcb->tx_window.next);
                    TCP_TCB_STATE_CHANGE("FIN-WAIT-1", "CLOSING");
                    tcb->state = tcb_t::CLOSING;
                } else {
                    // We are in the FIN-WAIT-1 state but we didn't send our FIN
                    // segment yet, as we still have data in the transmission
                    // queue.
                    //
                    // Continues in the LAST-ACK state as if we effectively
                    // received the FIN before the application layer asked to
                    // close the connection.

                    TCP_TCB_STATE_CHANGE("FIN-WAIT-1", "LAST-ACK");
                    tcb->state = tcb_t::LAST_ACK;
                }

                tcb->conn_handlers.remote_close();
                tcb->conn_handlers.close();
                break;
            case tcb_t::FIN_WAIT_2:
                ++tcb->rx_window.next;

                TCP_TCB_STATE_CHANGE("FIN-WAIT-2", "TIME-WAIT");
                tcb->state = tcb_t::TIME_WAIT;

                this->_schedule_fin_timeout(tcb_id, tcb);

                tcb->conn_handlers.remote_close();
                tcb->conn_handlers.close();
                break;
            case tcb_t::TIME_WAIT:
                // When in the TIME-WAIT state, this could only be a
                // retransmission of the FIN. Restart the 2 MSL timeout.
                this->_reschedule_fin_timeout(tcb);

                break;
            default:
                // Remains in the same state.
                break;
            };
        }

        //
        // Transmits any pending data that could have become ready as the
        // transmission window have been updated.
        //
        // Does this after checking for the FIN control bit so these segments
        // can acknowledge its receipt.
        //

        if (tcb->in_state(
            tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::CLOSE_WAIT |
            tcb_t::LAST_ACK
        ))
            this->_respond_with_data_segments(tcb_id, tcb);

        //
        // Acknowledges any received data and/or the FIN control bit.
        //
        // Checks that there is still something to acknowledge (data segments
        // contains an acknowledgement number).
        //

        if (tcb->rx_window.acked < tcb->rx_window.next)
            this->_respond_with_ack_segment(tcb_id, tcb);
    }

    // Retransmits the oldest unacked segment.
    //
    // Called by the retransmission timer and by the fast recovery algorithm
    // when receiving a third duplicate ack.
    void _retransmit(tcb_id_t tcb_id, tcb_t *tcb)
    {
        if (tcb->in_state(tcb_t::SYN_SENT)) {
            TCP_TCB_DEBUG("Retransmits a SYN segment");

            this->_send_syn_ack_segment(
                tcb_id, tcb, tcb->tx_window.unack, tcb->rx_window.next
            );
        } else if (tcb->in_state(tcb_t::SYN_RECEIVED)) {
            TCP_TCB_DEBUG("Retransmits a SYN/ACK segment");

            // TODO: sends a SYN segment.
        } else if (
            tcb->in_state(tcb_t::FIN_WAIT_1 | tcb_t::CLOSING | tcb_t::LAST_ACK)
            && tcb->tx_history.empty()
        ) {
            TCP_TCB_DEBUG("Retransmits a FIN segment");

            this->_send_fin_ack_segment(
                tcb_id, tcb, tcb->tx_window.next, tcb->rx_window.next
            );
        } else {
            TCP_TCB_DEBUG("Retransmits a data segment");

            typename tcb_t::tx_history_entry_t *segment =
                &tcb->tx_history.front();
            segment->retransmitted = true;

            seq_t seq       = tcb->tx_window.unack,
                  end_seq   = segment->end;

            assert(end_seq <= tcb->tx_window.next);

            // Counts the number of entries in the transmission queues that will
            // be transmitted in this segment. Does this before to only perform
            // a single dynamic allocation of the 'to_send' vector.

            size_t n_unack_entries     = 0,
                   n_not_sent_entries  = 0;
            for (
                auto it = tcb->tx_queue_sent_unack.begin();
                ;
                ++it
            ) {
                if (it == tcb->tx_queue_sent_unack.end()) {
                    // We reached the end of the unacked transmission queue.
                    // The last entry should be partially transmitted and still
                    // in the 'tx_queue_not_sent' queue.
                    assert(!tcb->tx_queue_not_sent.empty());
                    assert(tcb->tx_queue_not_sent.front().end >= end_seq);

                    n_not_sent_entries = 1;

                    break;
                }

                // Paranoia checks.
                assert(it->end > it->begin);
                assert(it->end > seq);

                ++n_unack_entries;

                if (it->end >= end_seq)
                    break;
            }

            size_t n_entries = n_unack_entries + n_not_sent_entries;
            assert(n_entries > 0);
            assert(n_not_sent_entries == 0 || n_not_sent_entries == 1);

            // Allocates and copies the entries to transmit in the 'to_send'
            // vector.

            auto to_send = allocate_shared<to_send_vec_t>(
                this->alloc, n_entries, this->alloc
            );

            copy(
                tcb->tx_queue_sent_unack.begin(),
                tcb->tx_queue_sent_unack.begin() + n_unack_entries,
                to_send->begin()
            );

            copy(
                tcb->tx_queue_not_sent.begin(),
                tcb->tx_queue_not_sent.begin() + n_not_sent_entries,
                to_send->begin() + n_unack_entries
            );

            // Sends the segment.

            size_t payload_size = (end_seq - seq).value;
            bool has_fin =    tcb->in_state(tcb_t::FIN_WAIT_1 | tcb_t::LAST_ACK)
                           && tcb->tx_queue_not_sent.empty()
                           && tcb->tx_queue_sent_unack.back().end == end_seq;

            this->_send_data_segment(
                tcb_id, tcb, seq, to_send, to_send->begin(), to_send->end(),
                payload_size, has_fin
            );
        }
    }

    #undef IGNORE_SEGMENT

    // -------------------------------------------------------------------------

    //
    // TCB handling helpers
    //

    // Destroys resources allocated to a TCP connection.
    void _destroy_tcb(tcb_id_t tcb_id)
    {
        auto it = this->tcbs.find(tcb_id);
        assert(it != this->tcbs.end());

        // TODO: reuse the 'tcbs' iterator to remove the TCB.

        this->_destroy_tcb(tcb_id, &it->second);
    }

    // Destroys resources allocated to a TCP connection.
    void _destroy_tcb(tcb_id_t tcb_id, tcb_t *tcb)
    {
        switch (tcb->state) {
        case tcb_t::SYN_SENT:
            TCP_TCB_STATE_CHANGE("SYN-SENT", "CLOSED");
            break;
        case tcb_t::SYN_RECEIVED:
            TCP_TCB_STATE_CHANGE("SYN-RECEIVED", "CLOSED");
            break;
        case tcb_t::ESTABLISHED:
            TCP_TCB_STATE_CHANGE("ESTABLISHED", "CLOSED");
            break;
        case tcb_t::FIN_WAIT_1:
            TCP_TCB_STATE_CHANGE("FIN-WAIT-1", "CLOSED");
            break;
        case tcb_t::FIN_WAIT_2:
            TCP_TCB_STATE_CHANGE("FIN-WAIT-2", "CLOSED");
            break;
        case tcb_t::CLOSE_WAIT:
            TCP_TCB_STATE_CHANGE("CLOSE-WAIT", "CLOSED");
            break;
        case tcb_t::CLOSING:
            TCP_TCB_STATE_CHANGE("CLOSING", "CLOSED");
            break;
        case tcb_t::LAST_ACK:
            TCP_TCB_STATE_CHANGE("LAST-ACK", "CLOSED");
            break;
        case tcb_t::TIME_WAIT:
            TCP_TCB_STATE_CHANGE("TIME-WAIT", "CLOSED");
            break;
        };

        if (tcb->has_timer)
            this->timers->remove(tcb->timer);

        this->tcbs.erase(tcb_id);
    }

    // Destroys resources allocated to a TCP connection and signal
    // application layer that the connection has been resetted.
    void _reset_tcb(tcb_id_t tcb_id, tcb_t *tcb)
    {
        if (tcb->in_state(
            tcb_t::SYN_SENT | tcb_t::SYN_RECEIVED | tcb_t::ESTABLISHED |
            tcb_t::FIN_WAIT_1 | tcb_t::FIN_WAIT_2 | tcb_t::CLOSE_WAIT
        )) {
            tcb->conn_handlers.reset();

            // Reloads the TCB has it could have been reallocated while calling
            // the handler.
            tcb = &this->tcbs.find(tcb_id)->second;
        }

        this->_destroy_tcb(tcb_id, tcb);
    }

    // -------------------------------------------------------------------------
    //
    // Timers
    //

    // TODO: move these methods into tcb_t

    // Removes the previous timer (if any) by the new one.
    void _replace_timer(
        tcb_t *tcb, typename clock_t::interval_t delay, function<void()> f
    )
    {
        if (tcb->has_timer)
            this->timers->remove(tcb->timer);
        else
            tcb->has_timer = true;

        tcb->timer = this->timers->schedule(delay, f);
    }

    // Reschedules the same timeout with a new delay.
    void _reschedule_timer(tcb_t *tcb, typename clock_t::interval_t new_delay)
    {
        assert(tcb->has_timer);
        tcb->timer = this->timers->reschedule(tcb->timer, new_delay);
    }

    void _unschedule_timer(tcb_t *tcb)
    {
        assert(tcb->has_timer);
        this->timers->remove(tcb->timer);
        tcb->has_timer = false;
    }

    void _schedule_retransmission_timer(tcb_id_t tcb_id, tcb_t *tcb)
    {
        this->_replace_timer(
            tcb, tcb->rtt.rto,
            [this, tcb_id]()
            {
                // Reloads the TCB has it could have been reallocated.
                auto it = this->tcbs.find(tcb_id);
                assert(it != this->tcbs.end());

                tcb_t *tcb = &it->second;

                TCP_TCB_DEBUG("Retransmission timeout");

                // RFC 5681 page 5: reuses the slow start algorithm.
                tcb->tx_window.reset_cwnd();

                // RFC 6298 page 5: doubles the timeout delay after a timeout.
                tcb->rtt.rto *= 2;

                this->_schedule_retransmission_timer(tcb_id, tcb);

                // RFC 6298 page 5: retransmits the oldest unacked segment.
                this->_retransmit(tcb_id, tcb);
            }
        );
    }

    void _reschedule_retransmission_timer(tcb_t *tcb)
    {
        this->_reschedule_timer(tcb, tcb->rtt.rto);
    }

    // Schedules the last timeout used to close a TCP connection, while in the
    // TIME-WAIT state.
    void _schedule_fin_timeout(tcb_id_t tcb_id, tcb_t *tcb)
    {
        this->_replace_timer(
            tcb, FIN_TIMEOUT,
            [this, tcb_id]()
            {
                // Reloads the TCB has it could have been reallocated.
                auto it = this->tcbs.find(tcb_id);
                assert(it != this->tcbs.end());

                this->_destroy_tcb(tcb_id, &it->second);
            }
        );
    }

    // Restarts the FIN timeout. The last scheduled timer for this TCB must be
    // a FIN timeout.
    void _reschedule_fin_timeout(tcb_t *tcb)
    {
        this->_reschedule_timer(tcb, FIN_TIMEOUT);
    }

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
                ++it;
        }
    }

    // Delivers the segment starting at the given segment number and containing
    // the given payload to the application layer. Updates the receiving window
    // accordingly.
    //
    // The payload must contain at least the next byte to receive (see
    // 'rx_window_t::contains_next()').
    void _deliver_to_app_layer(
        seq_t seq, cursor_t payload, size_t payload_size, tcb_t *tcb
    )
    {
        assert(payload_size > 0);
        assert(tcb->rx_window.contains_next(seq, payload_size));

        // Removes bytes which have already been received or which are after the
        // window.
        seq_t payload_offset = tcb->rx_window.next - seq;
        payload = payload.drop(payload_offset.value)
                         .take(tcb->rx_window.size);

        tcb->rx_window.next += seq_t(payload_size);

        tcb->conn_handlers.new_data(payload);
    }

    // -------------------------------------------------------------------------

    //
    // Segment helpers
    //

    // Sends a SYN/ACK segment.
    //
    // <SEQ=seq><ACK=ack><CTL=SYN,ACK>
    void _send_syn_ack_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        options_t options = { (typename options_t::mss_option_t) this->mss };
        this->_send_segment(
            tcb_id, seq, ack, _SYN_ACK_FLAGS, tcb->rx_window.size, options
        );
    }

    // Sends a FIN/ACK segment without a payload.
    //
    // <SEQ=seq><ACK=ack><CTL=FIN,ACK>
    void _send_fin_ack_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        this->_send_segment(
            tcb_id, seq, ack, _FIN_ACK_FLAGS, tcb->rx_window.size, EMPTY_OPTIONS
        );
    }

    // Sends a FIN/ACK segment with a payload.
    //
    // <SEQ=seq><ACK=ack><CTL=FIN,ACK><payload>
    inline void _send_fin_ack_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack,
        function<partial_sum_t(cursor_t)> payload_writer, size_t payload_size
    )
    {
        this->_send_segment(
            tcb_id, seq, ack, _FIN_ACK_FLAGS, tcb->rx_window.size,
            EMPTY_OPTIONS, payload_writer, payload_size
        );
    }

    // Sends an ACK segment with a payload.
    //
    // <SEQ=seq><ACK=ack><CTL=ACK><payload>
    inline void _send_ack_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack,
        function<partial_sum_t(cursor_t)> payload_writer, size_t payload_size
    )
    {
        this->_send_segment(
            tcb_id, seq, ack, _ACK_FLAGS, tcb->rx_window.size, EMPTY_OPTIONS,
            payload_writer, payload_size
        );
    }

    // Sends an ack segment without a payload.
    //
    // <SEQ=seq><ACK=ack><CTL=ACK>
    void _send_ack_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, net_t<seq_t> seq, net_t<seq_t> ack
    )
    {
        this->_send_segment(
            tcb_id, seq, ack, _ACK_FLAGS, tcb->rx_window.size, EMPTY_OPTIONS
        );
    }

    // Responds to the received segment by acknowledging the most recently
    // received byte.
    //
    // Updates the 'acked' field of the received window.
    //
    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>.
    void _respond_with_ack_segment(tcb_id_t tcb_id, tcb_t *tcb)
    {
        TCP_DEBUG(
            "Responds with ACK segment (<SEQ=%u><ACK=%u><CTL=ACK>)",
            tcb->tx_window.next.value, tcb->rx_window.next.value
        );

        this->_send_ack_segment(
            tcb_id, tcb, tcb->tx_window.next,
            tcb->rx_window.next
        );

        tcb->rx_window.acked = tcb->rx_window.next;
    }

    // Responds to the received segment by sending pending data (if any). Does
    // nothing of the transmission queue is empty or if the transmission window
    // has no free sequence number.
    //
    // The connection must be in a transmitting state (ESTABLISHED, FIN-WAIT-1,
    // CLOSE-WAIT or LAST-ACK).
    //
    // Can sent multiple data segments if permitted by the transmission window
    // and will update the transmission window and transmission queue.
    //
    // If the connection is in the FIN-WAIT-1 or LAST_ACK state, the FIN
    // control bit will be set in the segment holding the last data byte.
    //
    // Updates the 'acked' field of the received window.
    //
    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK><payload>.
    void _respond_with_data_segments(tcb_id_t tcb_id, tcb_t *tcb)
    {
        assert(tcb->in_state(
            tcb_t::ESTABLISHED | tcb_t::FIN_WAIT_1 | tcb_t::CLOSE_WAIT |
            tcb_t::LAST_ACK
        ));

        if (tcb->tx_queue_not_sent.empty())
            return;

        // First sequence number that is outside of the transmission window.
        seq_t end_of_win = tcb->tx_window.end();

        if (end_of_win <= tcb->tx_window.next)
            return;

        //
        // Copies the entries of the transmission queue that will be delivered
        // as the transmission queue could be reallocated when the transmission
        // occurs, and moves entirely transmitted entries to the
        // 'tx_queue_sent_unack' queue.
        //

        shared_ptr<vector<typename tcb_t::tx_queue_entry_t, alloc_t>> to_send;

        {
            // Counts the number of entries in the transmission window that will
            // be delivered.
            int n_entries = 0;
            for (
                auto it = tcb->tx_queue_not_sent.begin();
                it != tcb->tx_queue_not_sent.end() && end_of_win > it->begin;
                ++it
            ) {
                // Paranoia checks.
                assert(it->end > it->begin);
                assert(it->end > tcb->tx_window.next);
                ++n_entries;
            }

            assert(n_entries > 0);

            to_send = allocate_shared<to_send_vec_t>(
                this->alloc, n_entries, this->alloc
            );

            // Copies entries and moves entries that will be fully delivered to
            // the 'tx_queue_sent_unack' queue.
            for (int i = 0; i < n_entries; ++i) {
                const auto &entry = tcb->tx_queue_not_sent.front();

                (*to_send)[i] = entry;

                if (entry.end <= end_of_win) {
                    // Copies entries that will be entirely transmitted.
                    tcb->tx_queue_sent_unack.push_back(entry);
                    tcb->tx_queue_not_sent.pop_front();
                } else {
                    // Must be the last entry.
                    assert(i + 1 == n_entries);
                    break;
                }
            }
        }

        //
        // Sends the pending entries in one or more data segments.
        //

        // First sequence number which is outside of the transmission window or
        // not in the data to transmit.
        seq_t end_of_transmission = min(end_of_win, to_send->back().end);

        assert(end_of_transmission > tcb->tx_window.next);

        auto to_send_it = to_send->begin();

        do {
            // First sequence number that can't be send in this segment or
            // which is not in the data to send.
            seq_t end_of_seg = min(
                end_of_transmission,
                tcb->tx_window.next + (seq_t) tcb->tx_window.mss
            );

            size_t payload_size = (end_of_seg - tcb->tx_window.next).value;
            assert(payload_size > 0);
            assert(payload_size <= tcb->tx_window.mss);
            assert(payload_size <= tcb->tx_window.ready());

            assert(to_send_it != to_send->end());

            // Finds the first entry that will be sent in this segement.
            for (; to_send_it->end <= tcb->tx_window.next; ++to_send_it)
                ;

            // Finds the first entry that will not be sent in this segment.
            auto to_send_end_it = to_send_it + 1;
            for (
                ;
                   to_send_end_it != to_send->end()
                && to_send_end_it->end <= end_of_seg;
                ++to_send_end_it
            )
                ;

            bool has_fin =    tcb->in_state(tcb_t::FIN_WAIT_1 | tcb_t::LAST_ACK)
                           && tcb->tx_queue_not_sent.empty();

            this->_send_data_segment(
                tcb_id, tcb, tcb->tx_window.next,/* to_send, n_entries, */
                to_send, to_send_it, to_send_end_it,
                payload_size, has_fin
            );

            // Updates the transmission windows.

            tcb->tx_window.next += (seq_t) payload_size;

            tcb->rx_window.acked = tcb->rx_window.next;

            // Updates the transmission history.
            typename tcb_t::tx_history_entry_t segment(tcb->tx_window.next);
            tcb->tx_history.push_back(segment);

            if (has_fin)
                ++tcb->tx_window.next; // Transmitted FIN control bit.
        } while (end_of_transmission > tcb->tx_window.next);

        if (!tcb->has_timer)
            this->_schedule_retransmission_timer(tcb_id, tcb);
    }

    // Emits a segment to the remote TCP with data contained in the given
    // queue entries, and the FIN control bit if 'has_fin' is 'true'.
    //
    // The method will free the 'to_send' vector once the data will be
    // transmitted.
    //
    // <SEQ=seq><ACK=RCV.NXT><CTL=ACK><payload>.
    void _send_data_segment(
        tcb_id_t tcb_id, const tcb_t *tcb, seq_t seq,
        shared_ptr<to_send_vec_t> to_send,
        typename to_send_vec_t::const_iterator begin,
        typename to_send_vec_t::const_iterator end,
        size_t payload_size, bool has_fin
    )
    {
        assert(begin != end);

        // Creates a function which writes the content of multiple transmission
        // queue entries into a single network buffer.
        function<partial_sum_t(cursor_t)> payload_writer =
            [this, start_seq = seq, to_send, begin, end](cursor_t cursor)
            {
                assert(to_send->size() > 0);

                seq_t         seq = start_seq;
                partial_sum_t partial_sum = partial_sum_t::ZERO;

                for (auto it = begin; it != end; ++it) {
                    const auto &entry = *it;

                    assert(!cursor.empty());
                    assert(entry.begin <= seq);
                    assert(entry.end > seq);

                    size_t offset = (seq - entry.begin).value,
                           length = (entry.end - seq).value;

                    partial_sum = partial_sum.append(
                        entry.writer(offset, cursor.take(length))
                    );
                    cursor = cursor.drop(length);

                    seq = entry.end;
                }

                assert(cursor.empty());

                return partial_sum;
            };

        if (has_fin) {
            TCP_TCB_DEBUG(
                "Responds with FIN/ACK data segment "
                "(<SEQ=%u><ACK=%u><CTL=FIN,ACK><%zu bytes payload>)",
                seq.value, tcb->rx_window.next.value, payload_size
            );

            this->_send_fin_ack_segment(
                tcb_id, tcb, seq, tcb->rx_window.next, payload_writer,
                payload_size
            );
        } else {
            TCP_TCB_DEBUG(
                "Responds with data segment "
                "(<SEQ=%u><ACK=%u><CTL=ACK><%zu bytes payload>)",
                seq.value, tcb->rx_window.next.value, payload_size
            );

            this->_send_ack_segment(
                tcb_id, tcb, seq, tcb->rx_window.next, payload_writer,
                payload_size
            );
        }
    }

    // Responds to a received segment (and its payload) with a RST segment.
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

            TCP_DEBUG(
                "Responds with RST segment (<SEQ=0><ACK=%u><CTL=RST,ACK>)",
                ack.host().value
            );
        } else {
            seq     = hdr->ack;
            ack.net = 0;
            flags   = _RST_FLAGS;

            TCP_DEBUG(
                "Responds with RST segment (<SEQ=%u><CTL=RST>)",
                seq.host().value
            );
        }

        this->_send_segment(
            hdr->dport, saddr, hdr->sport, seq, ack, flags, 0, EMPTY_OPTIONS
        );
    }

    // Pushes the given segment with its payload to the network layer.
    void _send_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, options_t options,
        function<partial_sum_t(cursor_t)> payload_writer, size_t payload_size
    )
    {
        net_t<addr_t> saddr = this->network->addr;
        size_t seg_size = HEADER_SIZE + options.size() + payload_size;

        assert(seg_size - HEADER_SIZE <= this->mss);

        // Precomputes the sum of the pseudo header.
        partial_sum_t pseudo_hdr_sum =
            network_t::tcp_pseudo_header_sum(
                saddr, daddr, net_t<seg_size_t>(seg_size)
            );

        this->network->send_tcp_payload(
        daddr, seg_size,
        [sport, daddr, dport, seq, ack, flags, window, options, payload_writer,
         pseudo_hdr_sum]
        (cursor_t cursor) {
            // Delays the writing of the headers as the sum of the payload and
            // options is not yet known.
            cursor_t hdr_cursor = cursor;

            auto ret = _write_options(cursor.drop(HEADER_SIZE), options);
            cursor_t      payload_cursor = get<0>(ret);
            partial_sum_t options_sum    = get<1>(ret);
            size_t        options_size   = get<2>(ret);

            partial_sum_t payload_sum = payload_writer(payload_cursor);

            partial_sum_t partial_sum = pseudo_hdr_sum.append(options_sum)
                                                      .append(payload_sum);

            _write_header(
                hdr_cursor, sport, dport, seq, ack, flags, window, options_size,
                partial_sum
            );
        });
    }

    // Pushes the given segment with its payload to the network layer.
    inline void _send_segment(
        tcb_id_t tcb_id, net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, options_t options,
        function<partial_sum_t(cursor_t)> payload_writer, size_t payload_size
    )
    {
        this->_send_segment(
            tcb_id.lport, tcb_id.raddr, tcb_id.rport, seq, ack, flags, window,
            options, payload_writer, payload_size
        );
    }

    // Pushes the given segment with an empty payload to the network layer.
    inline void _send_segment(
        net_t<port_t> sport, net_t<addr_t> daddr, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, options_t options
    )
    {
        this->_send_segment(
            sport, daddr, dport, seq, ack, flags, window, options,
            [](cursor_t cursor) { return partial_sum_t::ZERO; }, 0
        );
    }

    // Pushes the given segment with an empty payload to the network layer.
    inline void _send_segment(
        tcb_id_t tcb_id, net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, options_t options
    )
    {
        this->_send_segment(
            tcb_id.lport, tcb_id.raddr, tcb_id.rport, seq, ack, flags, window,
            options
        );
    }

    // Writes the TCP header starting at the given buffer cursor.
    //
    // 'partial_sum' is the sum of the pseudo TCP header and of the payload.
    static cursor_t _write_header(
        cursor_t cursor, net_t<port_t> sport, net_t<port_t> dport,
        net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags,
        net_t<win_size_t> window, size_t options_size, partial_sum_t partial_sum
    );

    #undef TCP_TCB_STATE_CHANGE
    #undef TCP_TCB_ERROR
    #undef TCP_TCB_DEBUG

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
    // Returns the cursor to write data after the options, the partial sum of
    // the options, and the length of the option in bytes.
    static tuple<cursor_t, partial_sum_t, size_t> _write_options(
        cursor_t cursor, options_t options
    );

    static inline seq_t _get_current_tcp_seq(void);

    // -------------------------------------------------------------------------
};

//
// Initializes static fields and methods.
//

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::options_t
tcp_t<network_t, alloc_t>::EMPTY_OPTIONS = {
    tcp_t<network_t, alloc_t>::options_t::NO_MSS_OPTION
};

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::clock_t::interval_t
// tcp_t<network_t, alloc_t>::FIN_TIMEOUT(60 * 1000000);    // 60 seconds
tcp_t<network_t, alloc_t>::FIN_TIMEOUT(0);                  // Disabled

// Initializes common flags.

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_SYN_FLAGS(0, 0, 0, 0, 1 /* SYN */, 0);

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_SYN_ACK_FLAGS(0, 1 /* ACK */, 0, 0, 1 /* SYN */, 0);

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_FIN_ACK_FLAGS(0, 1 /* ACK */, 0, 0, 0, 1 /* FIN */);

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_ACK_FLAGS(0, 1 /* ACK */, 0, 0, 0, 0);

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_RST_FLAGS(0, 0, 0, 1 /* RST */, 0, 0);

template <typename network_t, typename alloc_t>
const typename tcp_t<network_t, alloc_t>::flags_t
tcp_t<network_t, alloc_t>::_RST_ACK_FLAGS(0, 1 /* ACK */, 0, 1 /* RST */, 0, 0);

// Defines static methods.

template <typename network_t, typename alloc_t>
typename tcp_t<network_t, alloc_t>::cursor_t
tcp_t<network_t, alloc_t>::_write_header(
    cursor_t cursor, net_t<port_t> sport, net_t<port_t> dport,
    net_t<seq_t> seq, net_t<seq_t> ack, flags_t flags, net_t<uint16_t> window,
    size_t options_size, partial_sum_t partial_sum
)
{
    return cursor.template write_with<header_t>(
    [sport, dport, seq, ack, flags, window, options_size, partial_sum]
    (header_t *hdr) {
        hdr->sport   = sport;
        hdr->dport   = dport;
        hdr->seq     = seq;
        hdr->ack     = ack;
        hdr->res     = 0;
        hdr->doff    = (HEADER_SIZE + options_size) / sizeof (uint32_t);
        hdr->flags   = flags;
        hdr->window  = window;
        hdr->check   = checksum_t::ZERO;
        hdr->urg_ptr = 0;

        hdr->check = checksum_t(
            partial_sum_t(hdr, HEADER_SIZE).append(partial_sum)
        );
    });
}

template <typename network_t, typename alloc_t>
typename tcp_t<network_t, alloc_t>::options_t
tcp_t<network_t, alloc_t>::_parse_options(
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
                ++data;
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

template <typename network_t, typename alloc_t>
tuple<typename tcp_t<network_t, alloc_t>::cursor_t, partial_sum_t, size_t>
tcp_t<network_t, alloc_t>::_write_options(cursor_t cursor, options_t options)
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

        return make_tuple(cursor, partial_sum, 4);
    } else
        return make_tuple(cursor, partial_sum_t::ZERO, 0);
}

template <typename network_t, typename alloc_t>
inline typename tcp_t<network_t, alloc_t>::seq_t
tcp_t<network_t, alloc_t>::_get_current_tcp_seq(void)
{
    return network_t::data_link_t::phys_t::get_current_tcp_seq();
}

#undef TCP_COLOR
#undef TCP_DEBUG
#undef TCP_ERROR

} } /* namespace rusty::net */

namespace std {

// 'std::hash<>' and 'std::equal_to<>' instances are required for TCB
// identifiers to be used in unordered containers.

using namespace rusty::net;

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

#endif /* __RUSTY_NET_TCP_HPP__ */

