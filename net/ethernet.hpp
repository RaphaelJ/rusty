//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to receive and send Ethernet frames.
//

#ifndef __TCP_MPIPE_NET_ETHERNET_HPP__
#define __TCP_MPIPE_NET_ETHERNET_HPP__

#include <cinttypes>
#include <cstring>
#include <functional>

#include <net/ethernet.h>   // ether_addr, ETHERTYPE_*
#include <netinet/ether.h>  // ether_ntoa

#include "net/arp.hpp"      // arp_t
#include "net/ipv4.hpp"     // ipv4_t
#include "util/macros.hpp"  // TCP_MPIPE_*, COLOR_*

namespace tcp_mpipe {
namespace net {

#define ETH_COLOR       COLOR_RED
#define ETH_DEBUG(MSG, ...)                                                    \
    TCP_MPIPE_DEBUG("ETH", ETH_COLOR, MSG, ##__VA_ARGS__)
#define ETH_ERROR(MSG, ...)                                                    \
    TCP_MPIPE_ERROR("ETH", ETH_COLOR, MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const uint16_t ETHERTYPE_ARP_NET = htons(ETHERTYPE_ARP);
static const uint16_t ETHERTYPE_IP_NET  = htons(ETHERTYPE_IP);

// Ethernet stack able to process frames from and to the specified physical
// 'phys_t' layer.
//
// The 'phys_t' type must provide the 'cursor_t' member type, the 'link_addr'
// member field and the method :
// 'send_packet(size_t payload_size, function<void(cursor_t)> payload_writer)'.
template <typename phys_t>
struct ethernet_t {
    //
    // Member types
    //

    typedef ethernet_t<phys_t>              this_t;

    typedef typename phys_t::cursor_t       cursor_t;
    typedef struct ether_addr               addr_t;

    // Upper network layers types.
    typedef ipv4_t<this_t>                  ipv4_ethernet_t;
    typedef arp_t<this_t, ipv4_ethernet_t>  arp_ethernet_ipv4_t;

    //
    // Static fields
    //

    static constexpr size_t   HEADERS_SIZE    = sizeof (ether_header);

    // 'arp_t' requires the following static fields:
    static constexpr uint16_t ARP_TYPE        = ARPHRD_ETHER;
    static constexpr size_t   ADDR_LEN        = ETH_ALEN;
    static constexpr addr_t   BROADCAST_ADDR  =
        { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

    //
    // Fields
    //

    // Interface Ethernet address (in network byte order).
    addr_t                          addr;

    // Physical layer instance.
    phys_t                          *phys;

    // Upper network layer instances.
    arp_ethernet_ipv4_t             arp;
    ipv4_t<ethernet_t<phys_t>>      ipv4;

    // Maximum payload size. Doesn't change after intialization.
    size_t                          max_payload_size;

    //
    // Methods
    //

    // Creates an Ethernet environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    ethernet_t(void)
    {
    }

    // Creates an Ethernet environment for the given physical layer
    // instance, Ethernet address and IPv4 address.
    //
    // Does the same thing as creating the environment with 'ethernet_t()' and
    // then calling 'init()'.
    ethernet_t(
        phys_t *_phys, addr_t _addr, typename ipv4_ethernet_t::addr_t ipv4_addr
    ) : phys(_phys), max_payload_size(_max_payload_size()), addr(_addr),
        arp(this, ipv4_addr), ipv4(this, &arp, ipv4_addr)
    {
    }

    // Initializes an Ethernet environment for the given physical layer
    // instance, Ethernet address and IPv4 address.
    void init(
        phys_t *_phys, addr_t _addr, typename ipv4_ethernet_t::addr_t ipv4_addr
    )
    {
        phys             = _phys;
        max_payload_size = _max_payload_size();
        addr             = _addr;
        arp.init(this, &ipv4);
        ipv4.init(this, &arp, ipv4_addr);
    }

    // Processes an Ethernet frame. The cursor must begin at the Ethernet layer
    // and must end at the end of the packet payload.
    //
    // This method is typically called by the physical layer when it receives
    // a packet.
    void receive_frame(cursor_t cursor)
    {
        if (UNLIKELY(cursor.size() < HEADERS_SIZE)) {
            ETH_ERROR("Frame ignored: too small to hold an Ethernet header");
            return;
        }

        cursor.template read_with<struct ether_header, void>(
        [this](const struct ether_header *hdr, cursor_t payload) {
            #define IGNORE_FRAME(WHY, ...)                                     \
                do {                                                           \
                    ETH_ERROR(                                                 \
                        "Frame from %s ignored: " WHY,                         \
                        addr_to_alpha(*((addr_t *) hdr->ether_shost)),         \
                        ##__VA_ARGS__                                          \
                    );                                                         \
                    return;                                                    \
                } while (0)

            static const addr_t broadcast_addr = BROADCAST_ADDR;

            if (UNLIKELY(
                   memcmp(&hdr->ether_dhost, &addr,           sizeof (addr_t))
                && memcmp(&hdr->ether_dhost, &broadcast_addr, sizeof (addr_t))
            ))
                IGNORE_FRAME("bad recipient");

            #define RECEIVE_FRAME()                                            \
                do {                                                           \
                    ETH_DEBUG(                                                 \
                        "Receives an Ethernet frame from %s",                  \
                        addr_to_alpha(*((addr_t *) hdr->ether_shost))          \
                    );                                                         \
                } while (0)

            if (hdr->ether_type == ETHERTYPE_ARP_NET) {
                RECEIVE_FRAME();
                arp.receive_message(payload);
            } else if (hdr->ether_type == ETHERTYPE_IP_NET) {
                RECEIVE_FRAME();
                ipv4.receive_datagram(payload);
            } else {
                IGNORE_FRAME(
                    "unknown Ethernet type (%" PRIu16 ")",
                    ntohs(hdr->ether_type)
                );
            }

            #undef RECEIVE_FRAME
            #undef IGNORE_FRAME
        });
    }

    // Creates an Ethernet frame with the given destination and Ethernet type,
    // and writes its payload with the given 'payload_writer'. The frame is then
    // transmitted to physical layer.
    //
    // 'dst' and 'ether_type' must be in network byte order.
    void send_payload(
        addr_t dst, uint16_t ether_type,
        size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        assert(payload_size >= 0 && payload_size <= max_payload_size);

        size_t frame_size = HEADERS_SIZE + payload_size;

        ETH_DEBUG(
            "Sends a %zu bytes ethernet frame to %s with type 0x%x",
            frame_size, addr_to_alpha(dst), ntohs(ether_type)
        );

        this->phys->send_packet(
            frame_size,
            [this, dst, ether_type, &payload_writer](cursor_t cursor) {
                cursor = _write_header(cursor, dst, ether_type);
                payload_writer(cursor);
            }
        );
    }

    // Equivalent to 'send_payload()' with 'ether_type' equals to
    // 'ETHERTYPE_ARP_NET'.
    //
    // This method is typically called by the ARP instance when it wants to send
    // a message.
    void send_arp_payload(
        addr_t dst, size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        send_payload(dst, ETHERTYPE_ARP_NET, payload_size, payload_writer);
    }

    // Equivalent to 'send_payload()' with 'ether_type' equals to
    // 'ETHERTYPE_IP_NET'.
    //
    // This method is typically called by the IPv4 instance when it wants to
    // send a packet.
    void send_ip_payload(
        addr_t dst, size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        send_payload(dst, ETHERTYPE_IP_NET, payload_size, payload_writer);
    }

    // Converts the Ethernet address to the standard hex-digits-and-colons
    // notation into a statically allocated buffer.
    //
    // This method is typically called by the ARP instance for debugging
    // messages.
    static char *addr_to_alpha(addr_t addr)
    {
        return ether_ntoa(&addr);
    }

private:

    // Writes the Ethernet header starting at the given buffer cursor.
    //
    // 'dst' and 'ether_type' must be in network byte order.
    cursor_t _write_header(cursor_t cursor, addr_t dst, uint16_t ether_type)
    {
        return cursor.template write_with<struct ether_header>(
        [this, dst, ether_type](struct ether_header *hdr) {
            mempcpy(&hdr->ether_dhost, &dst,  sizeof (addr_t));
            mempcpy(&hdr->ether_shost, &addr, sizeof (addr_t));
            hdr->ether_type = ether_type;
        });
    }

    size_t _max_payload_size(void)
    {
        // NOTE: doesn't support Jumbo frames.
        return min<size_t>(this->phys->max_packet_size - HEADERS_SIZE, 1500);
    }
};

#undef ETH_COLOR
#undef ETH_DEBUG
#undef ETH_ERROR

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_ETHERNET_HPP__ */
