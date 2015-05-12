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
#include <netinet/in.h>         // in_addr, IPPROTO_TCP
#include <netinet/ip.h>         // iphdr, IPDEFTTL, IPVERSION, IP_MF,
                                // IPPROTO_TCP, IPTOS_CLASS_DEFAULT

#include "net/checksum.hpp"

using namespace std;

namespace tcp_mpipe {
namespace net {

#define IPV4_COLOR     COLOR_CYN
#define IPV4_DEBUG(MSG, ...)                                                   \
    TCP_MPIPE_DEBUG("IPV4", IPV4_COLOR, MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const size_t   HEADERS_LEN   = // Headers size in 32 bit words.
    sizeof (struct iphdr) / sizeof (uint32_t);

template <typename data_link_t>
struct ipv4_t {
    //
    // Member types
    //

    typedef ipv4_t<data_link_t>             this_t;

    typedef typename data_link_t::cursor_t  cursor_t;

    typedef struct in_addr                  addr_t;
    typedef typename data_link_t::addr_t    data_link_addr_t;

    //
    // Static fields
    //

    // 'arp_t' requires the following static fields:
    static constexpr uint16_t   ARP_TYPE     = ETHERTYPE_IP;
    static constexpr size_t     ADDR_LEN     = 4;

    static constexpr size_t     HEADERS_SIZE = sizeof (struct iphdr);

    // Headers size in 32 bit words.
    static constexpr size_t     HEADERS_LEN  = HEADERS_SIZE / sizeof (uint32_t);

    //
    // Fields
    //

    // Lower network layer instances.
    data_link_t                 *data_link;
    arp_t<data_link_t, this_t>  *arp;

    // Instance's IPv4 address in network byte order.
    addr_t                      addr;

    // Maximum payload size. Doesn't change after intialization.
    size_t                      max_payload_size;

    // The current identification number used to indentify egressed datagrams.
    //
    // This counter is incremented by one each time a datagram is sent.
    uint16_t                    current_datagram_id = 0;

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
    // IPv4 address (in network byte order).
    //
    // Does the same thing as creating the environment with 'ipv4_t()' and then
    // calling 'init()'.
    ipv4_t(
        data_link_t *_data_link, arp_t<data_link_t, this_t> *_arp, addr_t _addr
    )
        : data_link(_data_link), arp(_arp), addr(_addr)
    {
    }

    // Initializes an IPv4 environment for the given data-link layer instance
    // and IPv4 address (in network byte order).
    void init(
        data_link_t *_data_link, arp_t<data_link_t, this_t> *_arp, addr_t _addr
    )
    {
        data_link = _data_link;
        arp       = _arp;
        addr      = _addr;
    }

    // Processes an IPv4 datagram wich starts at the given cursor (data-link
    // layer payload without headers).
    void receive_datagram(cursor_t cursor)
    {
        size_t cursor_size = cursor.size();

        if (UNLIKELY(cursor_size < HEADERS_SIZE)) {
            IPV4_DEBUG("Datagram ignored: too small to hold an IPv4 header");
            return;
        }

        cursor.template read_with<struct iphdr, void>(
        [this, cursor_size](const struct iphdr *hdr, cursor_t payload) {
            #define IGNORE_DATAGRAM(WHY, ...)                                  \
                do {                                                           \
                    IPV4_DEBUG(                                                \
                        "Datagram from %s ignored: " WHY,                      \
                        addr_to_alpha(*((addr_t *) &hdr->saddr)),              \
                        ##__VA_ARGS__                                          \
                    );                                                         \
                    return;                                                    \
                } while (0)

            //
            // Checks datagram validity.
            //

            if (UNLIKELY(hdr->version != IPVERSION)) {
                IGNORE_DATAGRAM(
                    "invalid IP version (received %u, excpected %u)",
                    hdr->version, IPVERSION
                );
            }

            if (hdr->ihl != HEADERS_LEN)
                IGNORE_DATAGRAM("options are not supported");

            size_t header_size = hdr->ihl * sizeof (uint32_t),
                   total_size  = ntohs(hdr->tot_len);

            if (UNLIKELY(total_size < header_size))
                IGNORE_DATAGRAM("total size is less than header size");

            if (UNLIKELY(cursor_size != total_size))
                IGNORE_DATAGRAM("total size is different from datagram size");

            uint16_t frag_off_host = ntohs(hdr->frag_off);
            if (UNLIKELY(
                   frag_off_host & IP_MF            // More fragment.
                || (frag_off_host & IP_OFFMASK) > 0 // Not the first fragment.
            ))
                IGNORE_DATAGRAM("fragmented datagrams are not supported");

            if (UNLIKELY(memcmp(&hdr->daddr, &addr, sizeof (addr_t))))
                IGNORE_DATAGRAM("bad recipient");

            if (UNLIKELY(checksum(hdr, HEADERS_SIZE) != 0))
                IGNORE_DATAGRAM("invalid checksum");

            //
            // Processes the datagram.
            //

            if (hdr->protocol == IPPROTO_TCP) {
                IPV4_DEBUG(
                    "Receives an IPv4 datagram from %s",
                    addr_to_alpha(*((addr_t *) &hdr->saddr))
                );
            } else {
                IGNORE_DATAGRAM(
                    "unknown IPv4 protocol (%u)", (unsigned int) hdr->protocol
                );
            }

            #undef IGNORE_DATAGRAM
        });
    }

    // Creates and push an IPv4 datagram with its payload to the daya-link layer
    // (L2).
    //
    // 'payload_writer' execution could be delayed after this function returns,
    // if an ARP transaction is required to translate the IPv4 address to its
    // corresponding data-link address. One should take care of not using memory
    // which could be deallocated before the 'payload_writer' execution.
    //
    // Returns 'true' if the 'payload_writer' execution has not been delayed.
    //
    // 'dst' and 'protocol' must be in network byte order.
    bool send_payload(
        addr_t dst, uint8_t protocol,
        size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        assert(payload_size >= 0 && payload_size <= max_payload_size);

        return this->arp->with_data_link_addr(
        dst, [this, dst, protocol, payload_size, payload_writer](
            const data_link_addr_t *data_link_dst
        ) {
            if (data_link_dst == nullptr) {
                IPV4_DEBUG("Unreachable address");
                return;
            }

            size_t datagram_size = HEADERS_SIZE + payload_size;

            ETH_DEBUG(
                "Sends a %zu bytes IPv4 datagram to %s with protocol "
                "%" PRIu16, datagram_size, addr_to_alpha(dst), protocol
            );

            // lock
            uint16_t datagram_id = current_datagram_id++;
            // unlock

            this->data_link->send_ip_payload(
            *data_link_dst, datagram_size,
            [dst, payload_writer, protocol, datagram_size, datagram_id]
            (cursor_t cursor) {
                cursor = _write_header(
                    cursor, datagram_size, datagram_id, protocol, dst
                );
                payload_writer(cursor);
            });
        });
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

private:

    // Writes the IPv4 header starting at the given buffer cursor.
    //
    // 'dst' and 'protocol' must be in network byte order.
    cursor_t _write_header(
        cursor_t cursor, size_t datagram_size, uint16_t datagram_id,
        uint8_t protocol, addr_t dst
    )
    {
        static const uint16_t FRAG_OFF_NET   = htons(IP_DF);
        const static uint8_t  TTL_NET        = htons(IPDEFTTL);

        return cursor.template write_with<struct iphdr>(
        [this, datagram_size, datagram_id, protocol, dst](struct iphdr *hdr) {
            hdr->version  = IPVERSION;
            hdr->ihl      = HEADERS_LEN;
            hdr->tos      = IPTOS_CLASS_DEFAULT;
            hdr->tot_len  = htons(datagram_size);
            hdr->id       = datagram_id;
            hdr->frag_off = FRAG_OFF_NET;
            hdr->ttl      = TTL_NET;
            hdr-protocol  = protocol;
            hdr->check    = 0;
            memcpy(&hdr->saddr, &this->addr, sizeof (addr_t));
            memcpy(&hdr->daddr, &dst,        sizeof (addr_t));

            hdr->check    = checksum(hdr, sizeof (struct iphdr));
        });
    }

    size_t _max_payload_size(void)
    {
        return min(this->data_link->max_payload_size, 65535) - HEADERS_SIZE;
    }
};

#undef IPV4_COLOR
#undef IPV4_DEBUG

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
