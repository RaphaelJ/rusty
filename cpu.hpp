//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#ifndef __TCP_MPIPE_CPU_HPP__
#define __TCP_MPIPE_CPU_HPP__

// Binds the current task to the n-th available dataplane Tile (first CPU is 0).
//
// Fails if there is less than n + 1 dataplane Tiles.
void bind_to_dataplane(unsigned int n);

#endif /* __TCP_MPIPE_CPU_HPP__ */
