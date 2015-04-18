//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//
// Provides functions to manage dataplane Tiles.
//

#ifndef __TCP_MPIPE_CPU_HPP__
#define __TCP_MPIPE_CPU_HPP__

namespace tcp_mpipe {

// Binds the current task to the n-th available dataplane Tile (first CPU is 0).
//
// Fails if there is less than n + 1 dataplane Tiles.
void bind_to_dataplane(unsigned int n);

} /* namespace tcp_mpipe */

#endif /* __TCP_MPIPE_CPU_HPP__ */
