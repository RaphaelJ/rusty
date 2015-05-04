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

#include "net/arp.hpp"
#include "net/ipv4.hpp"
#include "util/macros.hpp"

namespace tcp_mpipe {
namespace net {

#define ETH_DEBUG(MSG, ...) TCP_MPIPE_DEBUG("[ETH] " MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const unsigned short int ETHERTYPE_ARP_NET = htons(ETHERTYPE_ARP);
static const unsigned short int ETHERTYPE_IP_NET  = htons(ETHERTYPE_IP);

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

    // 'arp_t' requires the following static fields:
    static constexpr unsigned short int ARP_TYPE        = ARPHRD_ETHER;
    static constexpr size_t             ADDR_LEN        = ETH_ALEN;
    static constexpr addr_t             BROADCAST_ADDR  =
        { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

    //
    // Fields
    //

    // Physical layer instance.
    phys_t                          *phys;

    // Interface Ethernet address (in network byte order).
    addr_t                          addr;

    arp_ethernet_ipv4_t             arp;
    ipv4_t<ethernet_t<phys_t>>      ipv4;

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
    ) : phys(_phys), addr(_addr), arp(this, ipv4_addr), ipv4(ipv4_addr)
    {
    }

    // Initializes an Ethernet environment for the given physical layer
    // instance, Ethernet address and IPv4 address.
    void init(
        phys_t *_phys, addr_t _addr, typename ipv4_ethernet_t::addr_t ipv4_addr
    )
    {
        phys = _phys;
        addr = _addr;
        ipv4.init(this, ipv4_addr);
        arp.init(this, &ipv4);
    }

    // Processes an Ethernet frame. The cursor must begin at the Ethernet layer
    // and must end at the end of the packet payload.
    //
    // This method is typically called by the physical layer when it receives
    // a packet.
    void receive_frame(cursor_t cursor)
    {
        struct ether_header hdr;
        cursor = cursor.template read<struct ether_header>(&hdr);

        if (hdr.ether_type == ETHERTYPE_ARP_NET)
            this->arp.receive_message(cursor);
        else if (hdr.ether_type == ETHERTYPE_ARP_NET)
            TCP_MPIPE_DEBUG("Received IP Ethernet frame");
        else {
            ETH_DEBUG(
                "Received unknown Ethernet frame"
                "(Ether type: %" PRIu16 "). Ignore frame.",
                hdr.ether_type
            );
        }
    }

    // Creates an Ethernet frame with the given destination and Ethernet type,
    // and writes its payload with the given 'payload_writer'. The frame is then
    // transmitted to physical layer.
    //
    // 'dst' and 'ether_type' must be in network byte order.
    void send_frame(
        addr_t dst, uint16_t ether_type,
        size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        size_t headers_size = sizeof (ether_header),
               frame_size   = headers_size + payload_size;

        ETH_DEBUG(
            "Sends a %zu bytes ethernet frame to %s with type %" PRIu16,
            frame_size, ether_ntoa(&dst), ether_type
        );

        addr_t src = this->phys->link_addr;

        this->phys->send_packet(
            frame_size,
            [this, src, dst, ether_type, &payload_writer](cursor_t cursor) {
                cursor = _write_header(cursor, dst, ether_type);
                payload_writer(cursor);
            }
        );
    }

    // Equivalent to 'send_frame()' with 'ether_type' equals to
    // 'ETHERTYPE_ARP_NET'.
    //
    // This method is typically called by the ARP instance when it wants to send
    // a message.
    void send_arp_payload(
        addr_t dst, size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        send_frame(dst, ETHERTYPE_ARP_NET, payload_size, payload_writer);
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
    cursor_t _write_header(
        cursor_t cursor, addr_t dst, uint16_t ether_type
    )
    {
        return cursor.template write_with<struct ether_header>(
        [this, dst, ether_type](struct ether_header *hdr) {
                const addr_t *src = &(this->phys->link_addr);
                mempcpy(&(hdr->ether_dhost), &dst, sizeof (addr_t));
                mempcpy(&(hdr->ether_shost), src,  sizeof (addr_t));
                hdr->ether_type = ether_type;
        });
    }
};

#undef ETH_DEBUG

} } /* namespace tcp_mpipe::net */

#endif /* __TCP_MPIPE_NET_ETHERNET_HPP__ */
