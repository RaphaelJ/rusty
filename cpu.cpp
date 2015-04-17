//
// Copyright 2015 Raphael Javaux <raphaeljavaux@gmail.com>
// University of Liege.
//

#include <cstdio>
#include <cstdlib>
#include <errno.h>

#include <tmc/cpus.h>       // tmc_cpus_*
#include <sys/dataplane.h>  // set_dataplane

#include "common.hpp"

using namespace std;

void bind_to_dataplane(unsigned int n)
{
    int result;

    // Finds dataplane Tiles.
    cpu_set_t dataplane_cpu_set;
    result = tmc_cpus_get_dataplane_cpus(&dataplane_cpu_set);
    VERIFY_ERRNO(result, "tmc_cpus_get_dataplane_cpus()");

    unsigned int count = tmc_cpus_count(&dataplane_cpu_set);
    if (n + 1 > count) {
        DIE(
            "bind_to_dataplane(): not enough dataplane Tiles "
            "(%d requested, having %d)", n + 1, count
        );
    }

    // Binds itself to the first dataplane Tile.
    result = tmc_cpus_find_nth_cpu(&dataplane_cpu_set, n);
    VERIFY_ERRNO(result, "tmc_cpus_find_nth_cpu()");
    result = tmc_cpus_set_my_cpu(result);
    VERIFY_ERRNO(result, "tmc_cpus_set_my_cpu()");

    #ifdef DEBUG_DATAPLANE
    // Put dataplane tiles in "debug" mode. Interrupts other than page faults
    // will generate a kernel stacktrace.
    result = set_dataplane(DP_DEBUG);
    VERIFY_ERRNO(result, "set_dataplane()");
    #endif
}
