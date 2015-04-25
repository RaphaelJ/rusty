//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Manages ARP requests and responses.
//

#include <arpa/inet.h>      // htons(), in_addr, inet_ntoa()
#include <netinet/ether.h>  // ARPHRD_ETHER, ARPOP_REQUEST, ARPOP_REPLY,
                            // ETH_ALEN, ETHERTYPE_ARP, ETHERTYPE_IP,
                            // ether_addr, ether_arp, ether_ntoa()

#include "buffer.hpp"
#include "common.hpp"
#include "ethernet.hpp"
#include "mpipe.hpp"

#include "arp.hpp"

namespace tcp_mpipe {

#define ARP_DEBUG(MSG, ...) TCP_MPIPE_DEBUG("[ARP] " MSG, ##__VA_ARGS__)

static const struct ether_addr BROADCAST_ETHER_ADDR =
    { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

// *_NET constants are network byte order constants.
static const unsigned short int ETHERTYPE_IP_NET  = htons(ETHERTYPE_IP);
static const unsigned short int ARPHRD_ETHER_NET  = htons(ARPHRD_ETHER);
static const unsigned short int ARPOP_REQUEST_NET = htons(ARPOP_REQUEST);
static const unsigned short int ARPOP_REPLY_NET   = htons(ARPOP_REPLY);

void arp_init(
    arp_env_t *arp_env, mpipe_env_t *mpipe_env, struct in_addr ipv4_addr
)
{
    arp_env->mpipe_env  = mpipe_env;
    arp_env->ether_addr = mpipe_ether_addr(mpipe_env);
    arp_env->ipv4_addr  = ipv4_addr;
}

// Adds the given IPv4 to Ethernet address mapping in the cache or updates the
// cache entry if it already exists.
//
// In case of a new address, executes pending requests callbacks linked to the
// IPv4 address, if any.
static void _arp_cache_update(
    arp_env_t *arp_env, struct ether_addr ether_addr, struct in_addr ipv4_addr
);

void arp_receive(arp_env_t *arp_env, buffer_cursor_t cursor)
{
    cursor.read_with<struct ether_arp>([arp_env](const struct ether_arp *msg) {

        #define IGNORE_ARP_MSG(WHY, ...)                                       \
            do {                                                               \
                ARP_DEBUG("Message ignored: " WHY, ##__VA_ARGS__);             \
                return;                                                        \
            } while (0)

        // Checks that the ARP message is for IPv4 over Ethernet.
        // Ignores the message otherwise.

        if (UNLIKELY(msg->arp_hrd != ARPHRD_ETHER_NET)) {
            IGNORE_ARP_MSG(
                "hardware is not Ethernet (received %hu, Ethernet is %hu)",
                msg->arp_hrd, ARPHRD_ETHER
            );
        }

        if (UNLIKELY(msg->arp_pro != ETHERTYPE_IP_NET)) {
            IGNORE_ARP_MSG(
                "protocol is not IPv4 (received %hu, IPv4 is %hu)",
                ntohs(msg->arp_hrd), ETHERTYPE_IP
            );
        }

        if (UNLIKELY(msg->arp_hln != ETH_ALEN)) {
            IGNORE_ARP_MSG(
                "length of hardware address is not that of an Ethernet address "
                "(received %u, Ethernet is %u)",
                (unsigned) msg->arp_hln, (unsigned) ETH_ALEN
            );
        }

        if (UNLIKELY(msg->arp_pln != 4)) {
            IGNORE_ARP_MSG(
                "length of hardware address is not that of an IPv4 address "
                "(received %u, IPv4 is %u)",
                (unsigned) msg->arp_pln, (unsigned) 4
            );
        }

        // Processes the ARP message.

        struct ether_addr *sdr_ether = (struct ether_addr *) &(msg->arp_sha);
        struct in_addr    *sdr_ipv4  = (struct in_addr    *) &(msg->arp_spa),
                          *tgt_ipv4  = (struct in_addr    *) &(msg->arp_tpa);

        if (msg->arp_op == ARPOP_REQUEST_NET) {
            _arp_cache_update(arp_env, *sdr_ether, *sdr_ipv4);

            if (tgt_ipv4->s_addr == arp_env->ipv4_addr.s_addr) {
                // Someone is asking for our Ethernet address.
                // Sends an ARP reply with our IPv4 address to the host which
                // sent the request.

                ARP_DEBUG(
                    "Replies to %s (%s)", inet_ntoa(*sdr_ipv4),
                    ether_ntoa(sdr_ether)
                );

                arp_send_message(
                    arp_env, ARPOP_REPLY_NET, arp_env->ether_addr,
                    arp_env->ipv4_addr, *sdr_ether, *sdr_ipv4
                );
            }
        } else if (msg->arp_op == ARPOP_REPLY_NET)
            _arp_cache_update(arp_env, *sdr_ether, *sdr_ipv4);
        else
            IGNORE_ARP_MSG("unknown ARP opcode (%hu)", msg->arp_op);

        #undef IGNORE_ARP_MSG
    });
}

static inline buffer_cursor_t _arp_write_message(
    buffer_cursor_t cursor, unsigned short int op,
    struct ether_addr sdr_ether, struct in_addr sdr_ipv4,
    struct ether_addr tgt_ether, struct in_addr tgt_ipv4
);

// NOTE: inline ?
void arp_send_message(
    arp_env_t *arp_env, unsigned short int op,
    struct ether_addr sdr_ether, struct in_addr sdr_ipv4,
    struct ether_addr tgt_ether, struct in_addr tgt_ipv4
)
{
    ethernet_send_frame(
        arp_env->mpipe_env, sizeof (struct ether_arp), sdr_ether, tgt_ether,
        ETHERTYPE_ARP, [=](buffer_cursor_t cursor) {
            _arp_write_message(
                cursor, op, sdr_ether, sdr_ipv4, tgt_ether, tgt_ipv4
            );
        }
    );
}

static inline buffer_cursor_t _arp_write_message(
    buffer_cursor_t cursor, unsigned short int op,
    struct ether_addr sdr_ether, struct in_addr sdr_ipv4,
    struct ether_addr tgt_ether, struct in_addr tgt_ipv4
)
{
    return cursor.write_with<struct ether_arp>(
        [=](struct ether_arp *msg) {
            msg->arp_hrd = ARPHRD_ETHER_NET;
            msg->arp_pro = ETHERTYPE_IP_NET;

            msg->arp_hln = ETH_ALEN;
            msg->arp_pln = 4;

            *((struct ether_addr *) &(msg->arp_sha)) = sdr_ether;
            *((struct ether_addr *) &(msg->arp_tha)) = tgt_ether;

            *((struct in_addr *) &(msg->arp_spa)) = sdr_ipv4;
            *((struct in_addr *) &(msg->arp_tpa)) = tgt_ipv4;
        }
    );
}

static void _arp_cache_update(
    arp_env_t *arp_env, struct ether_addr ether_addr, struct in_addr ipv4_addr
)
{
    // NOTE: this procedure should require an exclusive lock for addrs_cache
    // and pending_reqs in case of multiple threads executing it.

    // lock

    auto p = arp_env->addrs_cache.insert({ ipv4_addr, ether_addr });

    if (!p.second) {
        // Address already in cache, replace the previous value if different.

        struct ether_addr *value = &(p.first->second);

        if (UNLIKELY(memcmp(value, &ether_addr, sizeof (struct ether_addr)))) {
            ARP_DEBUG(
                "Updates %s cache entry to %s (was %s)", inet_ntoa(ipv4_addr),
                ether_ntoa(&ether_addr), ether_ntoa(value)
            );
            *value = ether_addr;
        }

        // unlock
    } else {
        // The address was not in cache. Checks for pending requests.

        ARP_DEBUG(
            "New cache entry (%s is %s)", inet_ntoa(ipv4_addr),
            ether_ntoa(&ether_addr)
        );

        auto it = arp_env->pending_reqs.find(ipv4_addr);

        if (it != arp_env->pending_reqs.end()) {
            // The address has pending requests.
            //
            // As it's possible that one of these callbacks induce a new lookup
            // to the ARP cache for the same address, and thus a deadlock, we
            // must first remove the pending requests entry and free the lock
            // before calling any callback.

            vector<arp_callback_t> callbacks = move(it->second);
            arp_env->pending_reqs.erase(it);

            // unlock

            ARP_DEBUG(
                "Executes %d pending callbacks for %s", (int) callbacks.size(),
                inet_ntoa(ipv4_addr)
            );

            for (arp_callback_t& callback : callbacks)
                callback(ether_addr);
        } else {
            // No pending request.
            // unlock
        }
    }
}

bool arp_with_ether_addr(
    arp_env_t *arp_env, struct in_addr ipv4_addr, arp_callback_t callback
)
{
    // lock

    auto it = arp_env->addrs_cache.find(ipv4_addr);

    if (it != arp_env->addrs_cache.end()) { // Hardware address is cached.
        // unlock
        callback(it->second);
        return true;
    } else {                                // Hardware address is NOT cached.
        vector<arp_callback_t> callbacks { callback };
        auto p = arp_env->pending_reqs.emplace(make_pair(ipv4_addr, callbacks));

        if (!p.second) {
            // The pending request entry already existed. A request has already
            // been broadcasted for this IPv4 address. Simple adds the callback
            // to the vector.

            p.first->second.push_back(callback);

            // unlock
        } else {
            // No previous pending request entry.
            // Broadcasts an ARP request for this IPv4 address.

            // unlock

            arp_send_message(
                arp_env, ARPOP_REQUEST_NET,
                arp_env->ether_addr, arp_env->ipv4_addr,
                BROADCAST_ETHER_ADDR, ipv4_addr
            );
        }

        return false;
    }
}

#undef ARP_DEBUG

} /* namespace tcp_mpipe */
