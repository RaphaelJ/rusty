//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Manages ARP packets.
//

#ifndef __TCP_MPIPE_ARP_HPP__
#define __TCP_MPIPE_ARP_HPP__

namespace tcp_mpipe {

struct arp_env_t {
    
};

void arp_init(arp_env_t *arp_env, mpipe_env_t *mpipe_env);

} /* namespace tcp_mpipe */

#endif /* __TCP_MPIPE_ARP_HPP__ */
