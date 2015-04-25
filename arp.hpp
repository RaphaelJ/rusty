//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Manages ARP requests and responses.
//

#ifndef __TCP_MPIPE_ARP_HPP__
#define __TCP_MPIPE_ARP_HPP__

#include <cstring>
#include <functional>
#include <unordered_map>

#include "mpipe.hpp"

namespace std {

// 'std::hash<struct in_addr>' and 'std::equal_to<struct in_addr>' instances are
// required for IPv4 addresses to be used in unordered containers.

template <>
struct hash<struct in_addr> {
    inline size_t operator()(const struct in_addr &ipv4_addr) const
    {
        return hash<uint32_t>()((uint32_t) ipv4_addr.s_addr);
    }
};

template <>
struct equal_to<struct in_addr> {
    inline bool operator()(
        const struct in_addr& a, const struct in_addr& b
    ) const
    {
        return memcmp(&a, &b, sizeof (struct ether_addr)) == 0;
    }
};

}

using namespace std;

namespace tcp_mpipe {

// Callback used in the call of 'arp_with_ether_addr()'.
typedef function<void(struct ether_addr)> arp_callback_t;

struct arp_env_t {
    mpipe_env_t                                             *mpipe_env;

    // Ethernet address of the mPIPE interface (in network byte order).
    struct ether_addr                                       ether_addr;

    // IPv4 address this ARP instance must announce (in network byte order).
    struct in_addr                                          ipv4_addr;

    // Contains mapping/cache of known IPv4 addresses to their Ethernet
    // addresses (both in network byte order).
    //
    // The set of known IPv4 addresses is disjoint with the set of addresses in
    // 'pending_reqs'.
    unordered_map<struct in_addr, struct ether_addr>        addrs_cache;

    // Contains a mapping of IPv4 addresses (in network byte order) for which an
    // ARP request has been broadcasted but no response has been received yet.
    // The value contains a vector of functions which must be called once the
    // ARP reply is received.
    //
    // The set of pending IPv4 addresses is disjoint with the set of addresses
    // in 'addrs_cache'.
    unordered_map<struct in_addr, vector<arp_callback_t>>   pending_reqs;
};

void arp_init(
    arp_env_t *arp_env, mpipe_env_t *mpipe_env, struct in_addr ipv4_addr
);

// Pushes the given ARP message on the Egress queue.
void arp_send_message(
    arp_env_t *arp_env, unsigned short int op,
    struct ether_addr sdr_ether, struct in_addr sdr_ipv4,
    struct ether_addr tgt_ether, struct in_addr tgt_ipv4
);

// Processes an ARP message wich starts at the given cursor (Ethernet payload
// without headers).
void arp_receive(arp_env_t *arp_env, buffer_cursor_t cursor);

// Executes the given callback function with the Ethernet address (in network
// byte order) corresponding to the given IPv4 address (in network byte order).
//
// The callback will receive an 'struct ether_addr' equals to 0 if the address
// is unreachable.
//
// The callback will immediately be executed if the mapping is in the cache
// (addrs_cache) but could be delayed if an ARP transaction is required.
//
// Returns 'true' if the address was in the ARP cache and the callback has been
// executed, or 'false' if the callback execution has been delayed because of an
// unknown IPv4 address.
//
// Example:
//
//      arp_with_ether_addr(arp_env, ipv4_addr, [=](auto ether_addr) {
//          printf(
//              "%s hardware address is %s\n", inet_ntoa(ipv4_addr),
//              ether_ntoa(ether_addr)
//          );
//      });
//
bool arp_with_ether_addr(
    arp_env_t *arp_env, struct in_addr ipv4_addr, arp_callback_t callback
);

} /* namespace tcp_mpipe */

#endif /* __TCP_MPIPE_ARP_HPP__ */
