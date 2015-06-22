//
// Provides a template for type-safe network byte order types.
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

#ifndef __TCP_MPIPE_NET_ENDIAN_HPP__
#define __TCP_MPIPE_NET_ENDIAN_HPP__

#include <cstdint>
#include <cstring>
#include <functional>       // equal_to, hash
#include <utility>          // swap()

#include <arpa/inet.h>      // htonl(), htons(), ntohl(), ntons()
#include <endian.h>         // __BIG_ENDIAN, __BYTE_ORDER, __LITTLE_ENDIAN

using namespace std;

namespace tcp_mpipe {
namespace net {

// Provides two generic function to change the endianness of a data-type.
//
// The functions can be specialized for various types.

template <typename T>
inline T to_network(T host);

template <typename T>
inline T to_host(T net);

// Contains a value in network byte order.
//
// Use 'net_t<T>::net_t()' to construct a 'net_t' value from a host byte order
// value and 'net_t<T>::from_net()' to construct a 'net_t' value from a network
// byte order value.
//
// Use 'net_t<T>::net' to get the network byte order value and
// 'net_t<T>::host()' to get the host byte order value.
template <typename host_t>
struct net_t {
    //
    // Member types
    //

    typedef net_t<host_t>   this_t;

    //
    // Fields
    //

    // Value in network byte order.
    host_t                  net;

    // Initializes to an undefined value.
    inline net_t(void)
    {
    }

    // Initializes with an host byte order value.
    inline net_t(host_t host)
    {
        net = to_network<host_t>(host);
    }

    inline host_t host(void) const
    {
        return to_host<host_t>(net);
    }

    // Contructs a network byte order value from a value which is already in
    // network byte order.
    static inline net_t<host_t> from_net(host_t _net)
    {
        net_t<host_t> val;
        val.net = _net;
        return val;
    }

    inline net_t& operator=(this_t other)
    {
        net = other.net;
        return *this;
    }

    friend inline bool operator==(this_t a, this_t b)
    {
        return a.net == b.net;
    }

    friend inline bool operator!=(this_t a, this_t b)
    {
        return a.net != b.net;
    }

    friend inline bool operator==(this_t a, host_t b)
    {
        return a.host() == b;
    }

    friend inline bool operator!=(this_t a, host_t b)
    {
        return a.host() != b;
    }

    friend inline bool operator==(host_t a, this_t b)
    {
        return a == b.host();
    }

    friend inline bool operator!=(host_t a, this_t b)
    {
        return a != b.host();
    }

    friend inline this_t operator+(this_t a, this_t b)
    {
        return net_t<host_t>(a.host() + b.host());
    }

    friend inline this_t operator+(this_t a, host_t b)
    {
        return net_t<host_t>(a.host() + b);
    }

    friend inline this_t operator+(host_t a, this_t b)
    {
        return net_t<host_t>(a + b.host());
    }

    friend inline this_t operator-(this_t a, this_t b)
    {
        return net_t<host_t>(a.host() - b.host());
    }

    friend inline this_t operator-(this_t a, host_t b)
    {
        return net_t<host_t>(a.host() - b);
    }

    friend inline this_t operator-(host_t a, this_t b)
    {
        return net_t<host_t>(a - b.host());
    }
} __attribute__ ((__packed__));

//
// Specialized 'to_network()' and 'to_host()' instances for 'uint16_t' and
// 'uint32_t'.
//

template <>
inline uint16_t to_network(uint16_t host)
{
    return htons(host);
}


template <>
inline uint16_t to_host(uint16_t net)
{
    return ntohs(net);
}

template <>
inline uint32_t to_network(uint32_t host)
{
    return htonl(host);
}

template <>
inline uint32_t to_host(uint32_t net)
{
    return ntohl(net);
}

//
// Generic 'to_network()' and 'to_host()' instances.
//

// Reverse the bytes in the value.
template <typename T>
static inline T _change_endian(T value);

template <typename T>
inline T to_network(T host)
{
    return _change_endian(host);
}

template <typename T>
inline T to_host(T net)
{
    return _change_endian(net);
}

template <typename T>
static inline T _change_endian(T value)
{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t *value_bytes = (uint8_t *) &value;

        for (int i = 0; i < sizeof (T) / 2; i++) {
            swap<uint8_t>(
                value_bytes[i], value_bytes[sizeof (T) - 1 - i]
            );
        }

        return value;
    #elif __BYTE_ORDER == __BIG_ENDIAN
        return value;
    #else
        #error "Please set __BYTE_ORDER in <bits/endian.h>"
    #endif
}

} } /* namespace tcp_mpipe::net */

//
// 'std::equal_to<>' and 'std::hash<>' instances for 'net_t<>'.
//

namespace std {

using namespace tcp_mpipe::net;

template <>
template <typename host_t>
struct equal_to<net_t<host_t>> {
    inline bool operator()(const net_t<host_t>& a, const net_t<host_t>& b) const
    {
        return a == b;
    }
};

template <>
template <typename host_t>
struct hash<net_t<host_t>> {
    inline size_t operator()(const net_t<host_t> &value) const
    {
        return hash<host_t>()(value.net);
    }
};

} /* namespace std */

#endif /* __TCP_MPIPE_NET_ENDIAN_HPP__ */
