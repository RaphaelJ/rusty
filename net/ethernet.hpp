//
// Receives, processes and sends Ethernet frames.
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

#ifndef __RUSTY_NET_ETHERNET_HPP__
#define __RUSTY_NET_ETHERNET_HPP__

#include <cinttypes>
#include <cstring>
#include <functional>

#include <net/ethernet.h>   // ether_addr, ETHERTYPE_*
#include <netinet/ether.h>  // ether_ntoa(), ether_addr

#include "net/arp.hpp"      // arp_t
#include "net/endian.hpp"   // net_t
#include "net/ipv4.hpp"     // ipv4_t
#include "util/macros.hpp"  // RUSTY_*, COLOR_*

namespace rusty {
namespace net {

#define ETH_COLOR       COLOR_RED
#define ETH_DEBUG(MSG, ...)                                                    \
    RUSTY_DEBUG("ETH", ETH_COLOR, MSG, ##__VA_ARGS__)
#define ETH_ERROR(MSG, ...)                                                    \
    RUSTY_ERROR("ETH", ETH_COLOR, MSG, ##__VA_ARGS__)

// *_NET constants are network byte order constants.
static const net_t<uint16_t> ETHERTYPE_ARP_NET = ETHERTYPE_ARP;
static const net_t<uint16_t> ETHERTYPE_IP_NET  = ETHERTYPE_IP;

// Ethernet layer able to process frames from and to the specified physical
// 'phys_var_t' layer.
template <typename phys_var_t, typename alloc_t = allocator<char *>>
struct ethernet_t {
    //
    // Member types
    //

    // Redefines 'phys_var_t' as 'phys_t' so it can be accessible as a member
    // type.
    typedef phys_var_t                          phys_t;

    typedef ethernet_t<phys_t, alloc_t>         this_t;

    typedef typename phys_t::cursor_t           cursor_t;
    typedef typename phys_t::timer_manager_t    timer_manager_t;

    // Ethernet address.
    struct addr_t {
        uint8_t value[ETH_ALEN];

        inline addr_t &operator=(addr_t other)
        {
            memcpy(&value, &other.value, sizeof value);
            return *this;
        }

        friend inline bool operator==(addr_t a, addr_t b)
        {
            return !(a != b);
        }

        friend inline bool operator!=(addr_t a, addr_t b)
        {
            return memcmp(&a, &b, sizeof (addr_t));
        }

        static net_t<addr_t> from_ether_addr(struct ether_addr *ether_addr)
        {
            net_t<addr_t> addr;
            memcpy(addr.net.value, ether_addr->ether_addr_octet, ETH_ALEN);
            return addr;
        }

        // Converts the Ethernet address to the standard hex-digits-and-colons
        // notation into a statically allocated buffer.
        //
        // This method is typically called for debugging messages.
        static char *to_alpha(net_t<addr_t> addr)
        {
            return ether_ntoa((struct ether_addr *) &addr);
        }
    } __attribute__ ((__packed__));

    struct header_t {
        net_t<addr_t>   dhost;  // Destination Ethernet address.
        net_t<addr_t>   shost;  // Source Ethernet address.
        net_t<uint16_t> type;   // Ether-type.
    } __attribute__ ((__packed__));

    // Upper network layers types.
    typedef ipv4_t<this_t, alloc_t>                 ipv4_ethernet_t;
    typedef arp_t<this_t, ipv4_ethernet_t, alloc_t> arp_ethernet_ipv4_t;

    //
    // Static fields
    //

    static constexpr size_t         HEADER_SIZE     = sizeof (header_t);

    // 'arp_t' requires the following static fields:
    static constexpr uint16_t       ARP_TYPE        = ARPHRD_ETHER;
    static constexpr size_t         ADDR_LEN        = ETH_ALEN;

    static const net_t<addr_t>      BROADCAST_ADDR;

    //
    // Fields
    //

    net_t<addr_t>                   addr;

    // Physical layer instance.
    phys_t                          *phys;

    // Upper network layer instances.
    arp_ethernet_ipv4_t             arp;
    ipv4_ethernet_t                 ipv4;

    // Maximum payload size. Doesn't change after intialization.
    size_t                          max_payload_size;

    //
    // Methods
    //

    // Creates an Ethernet environment without initializing it.
    //
    // One must call 'init()' before using any other method.
    ethernet_t(alloc_t _alloc = alloc_t()) : arp(_alloc), ipv4(_alloc)
    {
    }

    // Creates an Ethernet environment for the given physical layer
    // instance, Ethernet address and IPv4 address.
    //
    // Does the same thing as creating the environment with 'ethernet_t()' and
    // then calling 'init()'.
    ethernet_t(
        phys_t *_phys, timer_manager_t *_timers, net_t<addr_t> _addr,
        net_t<typename ipv4_ethernet_t::addr_t> ipv4_addr,
        vector<typename arp_ethernet_ipv4_t::static_entry_t> static_arp_entries
            = vector<typename arp_ethernet_ipv4_t::static_entry_t>(),
        alloc_t _alloc = alloc_t()
    ) : phys(_phys), addr(_addr), arp(_alloc), ipv4(_alloc)
    {
        max_payload_size = _max_payload_size();
        arp.init(this, _timers, &ipv4, static_arp_entries);
        ipv4.init(this, &arp, ipv4_addr, _timers);
    }

    // Initializes an Ethernet environment for the given physical layer
    // instance, Ethernet address and IPv4 address.
    void init(
        phys_t *_phys, timer_manager_t *_timers, net_t<addr_t> _addr,
        net_t<typename ipv4_ethernet_t::addr_t> ipv4_addr,
        vector<typename arp_ethernet_ipv4_t::static_entry_t> static_arp_entries
            = vector<typename arp_ethernet_ipv4_t::static_entry_t>()
    )
    {
        phys             = _phys;
        max_payload_size = _max_payload_size();
        addr             = _addr;
        arp.init(this, _timers, &ipv4, static_arp_entries);
        ipv4.init(this, &arp, ipv4_addr, _timers);
    }

    // Processes an Ethernet frame. The cursor must begin at the Ethernet layer
    // and must end at the end of the packet payload.
    //
    // This method is typically called by the physical layer when it receives
    // a packet.
    void receive_frame(cursor_t cursor)
    {
        if (UNLIKELY(cursor.size() < HEADER_SIZE)) {
            ETH_ERROR("Frame ignored: too small to hold an Ethernet header");
            return;
        }

        cursor.template read_with<header_t, void>(
        [this](const header_t *hdr, cursor_t payload) {
            #define IGNORE_FRAME(WHY, ...)                                     \
                do {                                                           \
                    ETH_ERROR(                                                 \
                        "Frame from %s ignored: " WHY,                         \
                        addr_t::to_alpha(hdr->shost), ##__VA_ARGS__            \
                    );                                                         \
                    return;                                                    \
                } while (0)

            if (UNLIKELY(hdr->dhost != addr && hdr->dhost != BROADCAST_ADDR)) {
                IGNORE_FRAME(
                    "bad recipient (%s)", addr_t::to_alpha(hdr->dhost)
                );
            }

            #define RECEIVE_FRAME()                                            \
                do {                                                           \
                    ETH_DEBUG(                                                 \
                        "Receives an Ethernet frame from %s",                  \
                        addr_t::to_alpha(hdr->shost)                           \
                    );                                                         \
                } while (0)

            if (hdr->type == ETHERTYPE_ARP_NET) {
                RECEIVE_FRAME();
                arp.receive_message(payload);
            } else if (hdr->type == ETHERTYPE_IP_NET) {
                RECEIVE_FRAME();
                ipv4.receive_datagram(payload);
            } else {
                IGNORE_FRAME(
                    "unknown Ethernet type (%" PRIu16 ")", hdr->type.host()
                );
            }

            #undef RECEIVE_FRAME
            #undef IGNORE_FRAME
        });
    }

    // Creates an Ethernet frame with the given destination and Ethernet type,
    // and writes its payload with the given 'payload_writer'. The frame is then
    // transmitted to physical layer.
    void send_payload(
        net_t<addr_t> dst, net_t<uint16_t> ether_type,
        size_t payload_size, function<void(cursor_t)> payload_writer
    )
    {
        assert(payload_size >= 0 && payload_size <= max_payload_size);

        size_t frame_size = HEADER_SIZE + payload_size;

        ETH_DEBUG(
            "Sends a %zu bytes ethernet frame to %s with type 0x%x",
            frame_size, addr_t::to_alpha(dst), ether_type.host()
        );

        this->phys->send_packet(
        frame_size,
        [this, dst, ether_type, &payload_writer](cursor_t cursor) {
            cursor = _write_header(cursor, dst, ether_type);
            payload_writer(cursor);
        });
    }

    // Equivalent to 'send_payload()' with 'ether_type' equals to
    // 'ETHERTYPE_ARP_NET'.
    //
    // This method is typically called by the ARP instance when it wants to send
    // a message.
    inline void send_arp_payload(
        net_t<addr_t> dst, size_t payload_size,
        function<void(cursor_t)> payload_writer
    )
    {
        send_payload(dst, ETHERTYPE_ARP_NET, payload_size, payload_writer);
    }

    // Equivalent to 'send_payload()' with 'ether_type' equals to
    // 'ETHERTYPE_IP_NET'.
    //
    // This method is typically called by the IPv4 instance when it wants to
    // send a packet.
    inline void send_ip_payload(
        net_t<addr_t> dst, size_t payload_size,
        function<void(cursor_t)> payload_writer
    )
    {
        send_payload(dst, ETHERTYPE_IP_NET, payload_size, payload_writer);
    }

private:

    // Writes the Ethernet header starting at the given buffer cursor.
    cursor_t _write_header(
        cursor_t cursor, net_t<addr_t> dst, net_t<uint16_t> ether_type
    )
    {
        return cursor.template write_with<header_t >(
        [this, dst, ether_type, cursor](header_t *hdr) {
            hdr->dhost = dst;
            hdr->shost = addr;
            hdr->type  = ether_type;
        });
    }

    size_t _max_payload_size(void)
    {
        return this->phys->max_packet_size() - HEADER_SIZE;
    }
};

template <typename phys_t, typename alloc_t>
const net_t<typename ethernet_t<phys_t, alloc_t>::addr_t>
ethernet_t<phys_t, alloc_t>::BROADCAST_ADDR =
    { { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } };

#undef ETH_COLOR
#undef ETH_DEBUG
#undef ETH_ERROR

} } /* namespace rusty::net */

#endif /* __RUSTY_NET_ETHERNET_HPP__ */
