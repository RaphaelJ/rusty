//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Manages ARP requests and responses.
//

#ifndef __TCP_MPIPE_NET_ARP_HPP__
#define __TCP_MPIPE_NET_ARP_HPP__

#include <cstring>
#include <functional>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>      // htons()
#include <net/if_arp.h>     // ARPOP_REQUEST, ARPOP_REPLY

#include "util/macros.hpp"

using namespace std;

namespace tcp_mpipe {
namespace net {

#define ARP_DEBUG(MSG, ...) TCP_MPIPE_DEBUG("[ARP] " MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const uint16_t ARPOP_REQUEST_NET = htons(ARPOP_REQUEST);
static const uint16_t ARPOP_REPLY_NET   = htons(ARPOP_REPLY);

template <typename data_link_t, typename proto_t>
struct arp_t {
    //
    // Member types
    //

    typedef typename data_link_t::cursor_t  cursor_t;

    typedef typename data_link_t::addr_t    data_link_addr_t;
    typedef typename proto_t::addr_t        proto_addr_t;

    struct arp_message_t {
        struct arphdr       hdr;    // fixed-size header

        data_link_addr_t    sha;    // sender hardware address
        proto_addr_t        spa;    // sender protocol address

        data_link_addr_t    tha;    // target hardware address
        proto_addr_t        tpa;    // target protocol address
    } __attribute__((__packed__));

    // Callback used in the call of 'with_data_link_addr()'.
    typedef function<void(const data_link_addr_t *)>    callback_t;

    //
    // Static fields
    //

    const uint16_t DATA_LINK_TYPE_NET = htons(data_link_t::ARP_TYPE);
    const uint16_t PROTO_TYPE_NET     = htons(proto_t::ARP_TYPE);

    //
    // Fields
    //

    // Data-link layer instance.
    data_link_t                                         *data_link;
    // Protocol layer instance.
    proto_t                                             *proto;

    // Protocol address this ARP instance must announce (in network byte order).
    // TODO: use proto->addr instead.
    proto_addr_t                                        proto_addr;

    // Contains mapping/cache of known protocol addresses to their data-link
    // addresses (both in network byte order).
    //
    // The set of known protocol addresses is disjoint with the set of addresses
    // in 'pending_reqs'.
    unordered_map<proto_addr_t, data_link_addr_t>       addrs_cache;

    // Contains a mapping of protocol addresses (in network byte order) for
    // which an ARP request has been broadcasted but no response has been
    // received yet.
    // The value contains a vector of functions which must be called once the
    // ARP reply is received.
    //
    // The set of pending protocol addresses is disjoint with the set of
    // addresses in 'addrs_cache'.
    unordered_map<proto_addr_t, vector<callback_t>>     pending_reqs;

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
    arp_t(data_link_t *_data_link, proto_t *_proto)
        : data_link(_data_link), proto(_proto)
    {
    }

    // Initializes an ARP environment for the given data-link and protocol layer
    // instances.ipv4
    void init(data_link_t *_data_link, proto_t *_proto)
    {
        data_link = _data_link;
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
                ARP_DEBUG("Message ignored: " WHY, ##__VA_ARGS__);             \
                return;                                                        \
            } while (0)

        size_t cursor_size = cursor.size();

        if (UNLIKELY(cursor_size < sizeof (struct arphdr))) {
            IGNORE_MSG("too small to hold an ARP message's fixed-size header");
            return;
        }

        cursor.template read_with<arp_message_t>(
        [this, cursor_size](const arp_message_t *msg) {
            //
            // Checks that the ARP message is for the given data-link and
            // protocol layers.
            // Ignores the message otherwise.
            //

            if (UNLIKELY(msg->hdr.ar_hrd != DATA_LINK_TYPE_NET)) {
                IGNORE_MSG(
                    "invalid hardware type (received %hu, expected %hu)",
                    htons(msg->hdr.ar_hrd), data_link_t::ARP_TYPE
                );
            }

            if (UNLIKELY(msg->hdr.ar_pro != PROTO_TYPE_NET)) {
                IGNORE_MSG(
                    "invalid hardware type (received %hu, expected  %hu)",
                    htons(msg->hdr.ar_pro), proto_t::ARP_TYPE
                );
            }

            if (UNLIKELY(msg->hdr.ar_hln != data_link_t::ADDR_LEN)) {
                IGNORE_MSG(
                    "invalid hardware address size "
                    "(received %zu, expected %zu)",
                    (size_t) msg->hdr.ar_hln, (size_t) data_link_t::ADDR_LEN
                );
            }

            if (UNLIKELY(msg->hdr.ar_pln != proto_t::ADDR_LEN)) {
                IGNORE_MSG(
                    "invalid hardware address size "
                    "(received %zu, expected %zu)",
                    (size_t) msg->hdr.ar_pln, (size_t) proto_t::ADDR_LEN
                );
            }

            if (UNLIKELY(cursor_size < sizeof (arp_message_t)))
                IGNORE_MSG("too small to hold an ARP message");

            //
            // Processes the ARP message.
            //

            if (msg->hdr.ar_op == ARPOP_REQUEST_NET) {
                ARP_DEBUG(
                    "Receives an ARP request from %s (%s)",
                    proto_t::addr_to_alpha(msg->spa),
                    data_link_t::addr_to_alpha(msg->sha)
                );

                _cache_update(msg->sha, msg->spa);

                proto_addr_t *proto_addr = &this->proto->addr;

                if (!memcmp(&msg->tpa, proto_addr, sizeof (proto_addr_t))) {
                    // Someone is asking for our Ethernet address.
                    // Sends an ARP reply with our protocol address to the host
                    // which sent the request.

                    send_message(ARPOP_REPLY_NET, msg->sha, msg->spa);
                }
            } else if (msg->hdr.ar_op == ARPOP_REPLY_NET) {
                ARP_DEBUG(
                    "Receives an ARP reply from %s (%s)",
                    proto_t::addr_to_alpha(msg->spa),
                    data_link_t::addr_to_alpha(msg->sha)
                );

                _cache_update(msg->sha, msg->spa);
            } else
                IGNORE_MSG("unknown ARP opcode (%hu)", msg->hdr.ar_op);
        });

        #undef IGNORE_MSG
    }

    // Creates and push an ARP message to the data-link layer (L2).
    //
    // 'op', 'tha' and 'tpa' must be in network byte order.
    void send_message(uint16_t op, data_link_addr_t tha, proto_addr_t tpa)
    {
        #ifdef NDEBUG
            if (op == ARPOP_REQUEST_NET) {
                ARP_DEBUG(
                    "Requests for %s at %s", proto_t::addr_to_alpha(tpa),
                    data_link_t::addr_to_alpha(tha)
                );
            } else if (msg->arp_op == ARPOP_REPLY_NET) {
                ARP_DEBUG(
                    "Replies to %s (%s)", proto_t::addr_to_alpha(tpa),
                    data_link_t::addr_to_alpha(tha)
                );
            } else {
                DIE(
                    "Trying to send an ARP message with an invalid operation "
                    "code"
                );
            }
        #endif

        this->data_link->send_arp_payload(
            tha, sizeof (arp_message_t), [this, op, tha, tpa](cursor_t cursor) {
                _write_message(cursor, op, tha, tpa);
            }
        );
    }

    // Executes the given callback function by giving the data-link address (in
    // network byte order) corresponding to the given protocol address address
    // (in network byte order).
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
    bool with_data_link_addr(proto_addr_t proto_addr, callback_t callback)
    {
        // lock

        auto it = this->addrs_cache.find(proto_addr);

        if (it != this->addrs_cache.end()) {
            // Hardware address is cached.

            // unlock
            callback(&it->second);
            return true;
        } else {
            // Hardware address is NOT cached.

            vector<callback_t> callbacks { callback };
            auto p = this->pending_reqs.emplace(
                make_pair(proto_addr, callbacks)
            );

            if (!p.second) {
                // The pending request entry already existed. A request has
                // already been broadcasted for this protocol address. Simple
                // adds the callback to the vector.

                p.first->second.push_back(callback);

                // unlock
            } else {
                // No previous pending request entry.
                // Broadcasts an ARP request for this protocol address.

                // unlock

                this->send_message(
                    ARPOP_REQUEST_NET, data_link_t::BROADCAST_ADDR, proto_addr
                );
            }

            return false;
        }
    }

private:

    // Adds the given protocol to data-link layer address mapping in the cache
    // or updates cache entry if it already exists.
    //
    // In case of a new address, executes pending requests callbacks linked to
    // the protocol, if any.
    void _cache_update(data_link_addr_t data_link_addr, proto_addr_t proto_addr)
    {
        // NOTE: this procedure should require an exclusive lock for addrs_cache
        // and pending_reqs in case of multiple threads executing it.

        // lock

        auto p = this->addrs_cache.insert({ proto_addr, data_link_addr });

        if (!p.second) {
            // Address already in cache, replace the previous value if
            // different.

            data_link_addr_t *value = &p.first->second;

            bool change = memcmp(
                value, &data_link_addr, sizeof (data_link_addr_t)
            );

            if (UNLIKELY(change)) {
                ARP_DEBUG(
                    "Updates %s cache entry to %s (was %s)",
                    proto_t::addr_to_alpha(proto_addr),
                    data_link_t::addr_to_alpha(data_link_addr),
                    data_link_t::addr_to_alpha(*value)
                );
                *value = data_link_addr;
            }

            // unlock
        } else {
            // The address was not in cache. Checks for pending requests.

            ARP_DEBUG(
                "New cache entry (%s is %s)",
                proto_t::addr_to_alpha(proto_addr),
                data_link_t::addr_to_alpha(data_link_addr)
            );

            auto it = this->pending_reqs.find(proto_addr);

            if (it != this->pending_reqs.end()) {
                // The address has pending requests.
                //
                // As it's possible that one of these callbacks induce a new
                // lookup to the ARP cache for the same address, and thus a
                // deadlock, we must first remove the pending requests entry and
                // free the lock before calling any callback.

                vector<callback_t> callbacks = move(it->second);
                this->pending_reqs.erase(it);

                // unlock

                ARP_DEBUG(
                    "Executes %d pending callbacks for %s",
                    (int) callbacks.size(), proto_t::addr_to_alpha(proto_addr)
                );

                for (callback_t& callback : callbacks)
                    callback(&data_link_addr);
            } else {
                // No pending request.
                // unlock
            }
        }
    }

    // Writes the ARP message after the given buffer cursor.
    //
    // 'op', 'tha' and 'tpa' must be in network byte order.
    //
    // NOTE: inline ?
    cursor_t _write_message(
        cursor_t cursor, uint16_t op, data_link_addr_t tha, proto_addr_t tpa
    )
    {
        return cursor.template write_with<arp_message_t>(
            [this, op, tha, tpa](arp_message_t *msg) {
                msg->hdr.ar_hrd = DATA_LINK_TYPE_NET;
                msg->hdr.ar_pro = PROTO_TYPE_NET;

                msg->hdr.ar_hln = (uint8_t) data_link_t::ADDR_LEN;
                msg->hdr.ar_pln = (uint8_t) proto_t::ADDR_LEN;

                msg->hdr.ar_op = op;

                memcpy(
                    &msg->sha, &this->data_link->addr, sizeof (data_link_addr_t)
                );
                memcpy(&msg->spa, &this->proto->addr, sizeof (proto_addr_t));

                memcpy(&msg->tha, &tha, sizeof (data_link_addr_t));
                memcpy(&msg->tpa, &tpa, sizeof (proto_addr_t));
            }
        );
    }
};

#undef ARP_DEBUG

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_ARP_HPP__ */
