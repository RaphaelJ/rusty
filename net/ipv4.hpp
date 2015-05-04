//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to receive and send IPv4 datagrams.
//

#ifndef __TCP_MPIPE_NET_IPV4_HPP__
#define __TCP_MPIPE_NET_IPV4_HPP__

#include <cstring>
#include <functional>
#include <vector>

#include <arpa/inet.h>          // inet_ntoa
#include <net/ethernet.h>       // ETHERTYPE_IP
#include <netinet/in.h>         // in_addr

using namespace std;

namespace tcp_mpipe {
namespace net {

template <typename data_link_t>
struct ipv4_t {
    //
    // Member types
    //

    typedef typename data_link_t::cursor_t  cursor_t;
    typedef struct in_addr                  addr_t; // in network byte order.

    //
    // Static fields
    //

    // 'arp_t' requires the following static fields:
    static constexpr unsigned short int ARP_TYPE        = ETHERTYPE_IP;
    static constexpr const size_t       ADDR_LEN        = 4;

    //
    // Fields
    //

    // Data-link layer instance.
    data_link_t                     *data_link;

    // IPv4 address.
    addr_t                          addr;

    //
    // Methods
    //

    // Creates an IPv4 environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    ipv4_t(void)
    {
    }

    // Creates an IPv4 environment for the given data-link layer instance and
    // IPv4 address.
    //
    // Does the same thing as creating the environment with 'ipv4_t()' and then
    // calling 'init()'.
    ipv4_t(data_link_t *_data_link, addr_t _addr)
        : data_link(_data_link), addr(_addr)
    {
    }

    // Initializes an IPv4 environment for the given data-link layer instance
    // and IPv4 address.
    void init(data_link_t *_data_link, addr_t _addr)
    {
        data_link = _data_link;
        addr      = _addr;
    }

    // Processes an IP datagram wich starts at the given cursor (data-link layer
    // payload without headers).
    void receive_datagram(cursor_t cursor)
    {
    }

    // Creates and push an IP datagram with its payload to the daya-link layer
    // (L2).
    //
    // 'dst' and 'ether_type' must be in network byte order.
    void send_datagram(
        addr_t dst, /* transport_t trans_type, */
        size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
    }

    // Converts the IPv4 address to a string in IPv4 dotted-decimal notation
    // into a statically allocated buffer.
    //
    // This method is typically called by the ARP instance for debugging
    // messages.
    static char *addr_to_alpha(addr_t addr)
    {
        return inet_ntoa(addr);
    }
};

} } /* namespace tcp_mpipe::net */

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
        return memcmp(&a, &b, sizeof (struct in_addr)) == 0;
    }
};

} /* namespace std */

#endif /* __TCP_MPIPE_NET_IPV4_HPP__ */
