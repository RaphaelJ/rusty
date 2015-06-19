//
// Manages ARP requests and responses.
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

#ifndef __TCP_MPIPE_NET_ARP_HPP__
#define __TCP_MPIPE_NET_ARP_HPP__

#include <cstdint>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <vector>
#include <utility>          // move()

#include <net/if_arp.h>     // ARPOP_REQUEST, ARPOP_REPLY

#include "net/endian.hpp"   // net_t
#include "util/macros.hpp"  // TCP_MPIPE_*, COLOR_*

using namespace std;

namespace tcp_mpipe {
namespace net {

#define ARP_COLOR       COLOR_BLU
#define ARP_DEBUG(MSG, ...)                                                    \
    TCP_MPIPE_DEBUG("ARP", ARP_COLOR, MSG, ##__VA_ARGS__)
#define ARP_ERROR(MSG, ...)                                                    \
    TCP_MPIPE_ERROR("ARP", ARP_COLOR, MSG, ##__VA_ARGS__)
#define ARP_DIE(MSG, ...)                                                      \
    TCP_MPIPE_DIE(  "ARP", ARP_COLOR, MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const net_t<uint16_t> ARPOP_REQUEST_NET = ARPOP_REQUEST;
static const net_t<uint16_t> ARPOP_REPLY_NET   = ARPOP_REPLY;

template <typename data_link_t, typename proto_t>
struct arp_t {
    //
    // Member types
    //

    typedef typename data_link_t::cursor_t          cursor_t;
    typedef typename data_link_t::timer_manager_t   timer_manager_t;
    typedef typename timer_manager_t::timer_id_t    timer_id_t;
    typedef typename timer_manager_t::delay_t       delay_t;

    typedef typename data_link_t::addr_t            data_link_addr_t;
    typedef typename proto_t::addr_t                proto_addr_t;

    struct message_t {
        struct header_t {                   // fixed-size header
            net_t<uint16_t> hrd;    // format of hardware address
            net_t<uint16_t> pro;    // format of protocol address
            uint8_t         hln;    // length of hardware address
            uint8_t         pln;    // length of protocol address
            net_t<uint16_t> op;     // ARP opcode
        } __attribute__((__packed__)) hdr;

        net_t<data_link_addr_t>    sha;     // sender hardware address
        net_t<proto_addr_t>        spa;     // sender protocol address

        net_t<data_link_addr_t>    tha;     // target hardware address
        net_t<proto_addr_t>        tpa;     // target protocol address
    } __attribute__((__packed__));

    struct cache_entry_t {
        net_t<data_link_addr_t> addr;

        // Timer which triggers the expiration of the entry.
        timer_id_t              timer;
    };

    // Callback used in the call of 'with_data_link_addr()'.
    typedef function<void(const net_t<data_link_addr_t> *)> callback_t;

    struct pending_entry_t {
        vector<callback_t>  callbacks;

        // Timer which triggers the expiration of resolution.
        timer_id_t          timer;
    };

    //
    // Static fields
    //

    // Delay in microseconds (10^-6) before an ARP table entry will be removed.
    static constexpr delay_t    ENTRY_TIMEOUT   = 3600L * 1000000L;

    // Delay in microseconds (10^-6) to wait for an ARP resolution response.
    static constexpr delay_t    REQUEST_TIMEOUT = 5L * 1000000L;

    //
    // Fields
    //

    // Data-link layer instance.
    data_link_t             *data_link;

    timer_manager_t         *timers;

    // Protocol layer instance.
    proto_t                 *proto;


    const net_t<uint16_t>   DATA_LINK_TYPE_NET  = data_link_t::ARP_TYPE;
    const net_t<uint16_t>   PROTO_TYPE_NET      = proto_t::ARP_TYPE;

    // Contains mapping/cache of known protocol addresses to their data-link
    // addresses.
    //
    // The set of known protocol addresses is disjoint with the set of addresses
    // in 'pending_reqs'.
    unordered_map<net_t<proto_addr_t>, cache_entry_t>   addrs_cache;

    // Contains a mapping of protocol addresses for which an ARP request has
    // been broadcasted but no response has been received yet.
    // The value contains a vector of functions which must be called once the
    // ARP reply is received.
    //
    // The set of pending protocol addresses is disjoint with the set of
    // addresses in 'addrs_cache'.
    unordered_map<net_t<proto_addr_t>, pending_entry_t> pending_reqs;

    //
    // Methods
    //

    // Creates an ARP environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    arp_t(void)
    {
    }

    // Creates an ARP environment for the given data-link and protocol layer
    // instances.
    //
    // Does the same thing as creating the environment with 'arp_t()' and then
    // calling 'init()'.
    arp_t(data_link_t *_data_link, timer_manager_t *_timers, proto_t *_proto)
        : data_link(_data_link), timers(_timers), proto(_proto)
    {
    }

    // Initializes an ARP environment for the given data-link and protocol layer
    // instances.ipv4
    void init(
        data_link_t *_data_link, timer_manager_t *_timers, proto_t *_proto
    )
    {
        data_link = _data_link;
        timers    = _timers;
        proto     = _proto;
    }

    // Processes an ARP message wich starts at the given cursor (data-link frame
    // payload without data-link layer headers).
    //
    // This method is typically called by the data-link layer when it receives
    // a frame.
    void receive_message(cursor_t cursor)
    {
        #define IGNORE_MSG(WHY, ...)                                           \
            do {                                                               \
                ARP_ERROR("Message ignored: " WHY, ##__VA_ARGS__);             \
                return;                                                        \
            } while (0)

        size_t cursor_size = cursor.size();

        if (UNLIKELY(cursor_size < sizeof (typename message_t::header_t))) {
            IGNORE_MSG("too small to hold an ARP message's fixed-size header");
            return;
        }

        cursor.template read_with<message_t>(
        [this, cursor_size](const message_t *msg) {
            //
            // Checks that the ARP message is for the given data-link and
            // protocol layers.
            // Ignores the message otherwise.
            //

            if (UNLIKELY(msg->hdr.hrd != DATA_LINK_TYPE_NET)) {
                IGNORE_MSG(
                    "invalid hardware type (received %hu, expected %hu)",
                    msg->hdr.hrd.host(), data_link_t::ARP_TYPE
                );
            }

            if (UNLIKELY(msg->hdr.pro != PROTO_TYPE_NET)) {
                IGNORE_MSG(
                    "invalid hardware type (received %hu, expected  %hu)",
                    msg->hdr.pro.host(), proto_t::ARP_TYPE
                );
            }

            if (UNLIKELY(msg->hdr.hln != data_link_t::ADDR_LEN)) {
                IGNORE_MSG(
                    "invalid hardware address size "
                    "(received %zu, expected %zu)",
                    (size_t) msg->hdr.hln, (size_t) data_link_t::ADDR_LEN
                );
            }

            if (UNLIKELY(msg->hdr.pln != proto_t::ADDR_LEN)) {
                IGNORE_MSG(
                    "invalid hardware address size "
                    "(received %zu, expected %zu)",
                    (size_t) msg->hdr.pln, (size_t) proto_t::ADDR_LEN
                );
            }

            if (UNLIKELY(cursor_size < sizeof (message_t)))
                IGNORE_MSG("too small to hold an ARP message");

            //
            // Processes the ARP message.
            //

            if (msg->hdr.op == ARPOP_REQUEST_NET) {
                ARP_DEBUG(
                    "Receives an ARP request from %s (%s)",
                    proto_t::addr_t::to_alpha(msg->spa),
                    data_link_t::addr_t::to_alpha(msg->sha)
                );

                _cache_update(msg->sha, msg->spa);

                if (msg->tpa == this->proto->addr) {
                    // Someone is asking for our Ethernet address.
                    // Sends an ARP reply with our protocol address to the host
                    // which sent the request.

                    send_message(ARPOP_REPLY_NET, msg->sha, msg->spa);
                }
            } else if (msg->hdr.op == ARPOP_REPLY_NET) {
                ARP_DEBUG(
                    "Receives an ARP reply from %s (%s)",
                    proto_t::addr_t::to_alpha(msg->spa),
                    data_link_t::addr_t::to_alpha(msg->sha)
                );

                _cache_update(msg->sha, msg->spa);
            } else
                IGNORE_MSG("unknown ARP opcode (%hu)", msg->hdr.op.host());
        });

        #undef IGNORE_MSG
    }

    // Creates and push an ARP message to the data-link layer (L2).
    void send_message(
        net_t<uint16_t> op, net_t<data_link_addr_t> tha, net_t<proto_addr_t> tpa
    )
    {
        #ifndef NDEBUG
            if (op == ARPOP_REQUEST_NET) {
                ARP_DEBUG(
                    "Requests for %s at %s", proto_t::addr_t::to_alpha(tpa),
                    data_link_t::addr_t::to_alpha(tha)
                );
            } else if (op == ARPOP_REPLY_NET) {
                ARP_DEBUG(
                    "Replies to %s (%s)", proto_t::addr_t::to_alpha(tpa),
                    data_link_t::addr_t::to_alpha(tha)
                );
            } else {
                ARP_DIE(
                    "Trying to send an ARP message with an invalid operation "
                    "code"
                );
            }
        #endif

        this->data_link->send_arp_payload(
            tha, sizeof (message_t), [this, op, tha, tpa](cursor_t cursor) {
                _write_message(cursor, op, tha, tpa);
            }
        );
    }

    // Executes the given callback function by giving the data-link address
    // corresponding to the given protocol address address.
    //
    // The callback will receive a 'nullptr' as 'data_link_addr_t' if the
    // address is unreachable.
    //
    // The callback will immediately be executed if the mapping is in the cache
    // (addrs_cache) but could be delayed if an ARP transaction is required.
    //
    // Returns 'true' if the address was in the ARP cache and the callback has
    // been executed, or 'false' if the callback execution has been delayed
    // because of an unknown protocol address.
    //
    // Example with ARP for IPv4 over Ethernet:
    //
    //      arp.with_data_link_addr(ipv4_addr, [=](auto ether_addr) {
    //          printf(
    //              "%s hardware address is %s\n", inet_ntoa(ipv4_addr),
    //              ether_ntoa(ether_addr)
    //          );
    //      });
    //
    bool with_data_link_addr(
        net_t<proto_addr_t> proto_addr, callback_t callback
    )
    {
        // NOTE: this procedure should require an exclusive lock for addrs_cache
        // and pending_reqs in case of multiple threads executing it.

        // lock

        auto it_cache = this->addrs_cache.find(proto_addr);

        if (it_cache != this->addrs_cache.end()) {
            // Hardware address is cached.

            // unlock
            callback(&it_cache->second.addr);
            return true;
        } else {
            // Hardware address is NOT cached.
            //
            // Checks if a pending request exists for this address.

            auto it_pending = this->pending_reqs.find(proto_addr);

            if (it_pending != this->pending_reqs.end()) {
                // The pending request entry already existed. A request has
                // already been broadcasted for this protocol address.
                //
                // Simply adds the callback to the vector.

                it_pending->second.callbacks.push_back(callback);

                // unlock
            } else {
                // No previous pending request entry.
                //
                // Creates the entry with a new timer and broadcasts an ARP
                // request for this protocol address.

                auto p = this->pending_reqs.emplace(
                    proto_addr, pending_entry_t()
                );
                pending_entry_t *entry = &p.first->second;
                entry->callbacks.push_back(callback);

                entry->timer = timers->schedule(
                    REQUEST_TIMEOUT, [this, proto_addr]() {
                        this->_remove_pending_request(proto_addr);
                    }
                );

                // unlock

                this->send_message(
                    ARPOP_REQUEST_NET, data_link_t::BROADCAST_ADDR, proto_addr
                );
            }

            return false;
        }
    }

private:

    // Removes a pending entry for the given protocol address.
    //
    // Doesn't unschedule the timer.
    void _remove_pending_request(net_t<proto_addr_t> addr)
    {
        ARP_DEBUG(
            "Removes pending request for %s", proto_t::addr_t::to_alpha(addr)
        );
        this->pending_reqs.erase(addr);
    }

    // Adds the given protocol to data-link layer address mapping in the cache
    // or updates cache entry if it already exists.
    //
    // In case of a new address, executes pending requests callbacks linked to
    // the protocol, if any.
    void _cache_update(
        net_t<data_link_addr_t> data_link_addr, net_t<proto_addr_t> proto_addr
    )
    {
        // NOTE: this procedure should require an exclusive lock for addrs_cache
        // and pending_reqs in case of multiple threads executing it.

        // lock

        // Schedules a timer to remove the entry after ENTRY_TIMEOUT.
        timer_id_t timer_id = timers->schedule(
            ENTRY_TIMEOUT, [this, proto_addr]()
            {
                this->_remove_cache_entry(proto_addr);
            }
        );

        cache_entry_t entry = { data_link_addr, timer_id };
        auto inserted = this->addrs_cache.emplace(proto_addr, entry);

        if (!inserted.second) {
            // Address already in cache, replace the previous value if
            // different.

            cache_entry_t *inserted_entry = &inserted.first->second;

            if (UNLIKELY(inserted_entry->addr != data_link_addr)) {
                ARP_DEBUG(
                    "Updates %s cache entry to %s (was %s)",
                    proto_t::addr_t::to_alpha(proto_addr),
                    data_link_t::addr_t::to_alpha(data_link_addr),
                    data_link_t::addr_t::to_alpha(inserted_entry->addr)
                );
                inserted_entry->addr = data_link_addr;
            }

            // Replaces the old timeout.

            timers->remove(inserted_entry->timer);
            inserted_entry->timer = timer_id;

            // unlock
        } else {
            // The address was not in cache. Checks for pending requests.

            ARP_DEBUG(
                "New cache entry (%s is %s)",
                proto_t::addr_t::to_alpha(proto_addr),
                data_link_t::addr_t::to_alpha(data_link_addr)
            );

            auto it = this->pending_reqs.find(proto_addr);

            if (it != this->pending_reqs.end()) {
                // The address has pending requests.

                pending_entry_t *pending_entry = &it->second;

                // Removes the request timeout.
                timers->remove(pending_entry->timer);

                // As it's possible that one of these callbacks induce a new
                // lookup to the ARP cache for the same address, and thus a
                // deadlock, we must first remove the pending requests entry and
                // free the lock before calling any callback.

                vector<callback_t> callbacks = move(pending_entry->callbacks);
                this->pending_reqs.erase(it);

                // unlock

                ARP_DEBUG(
                    "Executes %d pending callbacks for %s",
                    (int) callbacks.size(),
                    proto_t::addr_t::to_alpha(proto_addr)
                );

                // Executes the callbacks.

                for (callback_t& callback : callbacks)
                    callback(&data_link_addr);
            } else {
                // No pending request.
                //
                // Occurs when the addres has not been requested.

                // unlock
            }
        }
    }

    // Removes the cache entry for the given protocol address.
    //
    // Doesn't unschedule the timer.
    void _remove_cache_entry(net_t<proto_addr_t> addr)
    {
        ARP_DEBUG(
            "Removes cache entry for %s", proto_t::addr_t::to_alpha(addr)
        );
        this->addrs_cache.erase(addr);
    }

    // Writes the ARP message after the given buffer cursor.
    //
    // NOTE: inline ?
    cursor_t _write_message(
        cursor_t cursor, net_t<uint16_t> op, net_t<data_link_addr_t> tha,
        net_t<proto_addr_t> tpa
    )
    {
        return cursor.template write_with<message_t>(
            [this, op, tha, tpa](message_t *msg) {
                msg->hdr.hrd = DATA_LINK_TYPE_NET;
                msg->hdr.pro = PROTO_TYPE_NET;

                msg->hdr.hln = (uint8_t) data_link_t::ADDR_LEN;
                msg->hdr.pln = (uint8_t) proto_t::ADDR_LEN;

                msg->hdr.op = op;

                msg->sha = this->data_link->addr;
                msg->spa = this->proto->addr;
                msg->tha = tha;
                msg->tpa = tpa;
            }
        );
    }
};

#undef ARP_COLOR
#undef ARP_DEBUG

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_ARP_HPP__ */
