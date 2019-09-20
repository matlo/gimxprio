/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include <sched.h>
#include <stdio.h>
#include <gimxcommon/include/gerror.h>
#include <gimxlog/include/glog.h>

GLOG_INST( GLOG_NAME)

static struct {
    int clients; // keep track of how many clients called gprio_init without calling gprio_end
    int policy;
    struct sched_param param;
} state = { .clients = 0, .policy = -1 };

void gprio_clean() {

    --state.clients;

    if (state.clients > 0) {
        return;
    }

    if (state.policy == -1) {
        return;
    }

    // Restore settings.

    if (sched_setscheduler(0, state.policy, &state.param) < 0) {
        PRINT_ERROR_ERRNO("sched_setscheduler");
    }

    state.policy = -1;
}

int gprio_init() {

    ++state.clients;

    if (state.clients > 1) {
        return 0;
    }

    // Get current settings.

    if (sched_getparam(0, &state.param) == -1) {
        PRINT_ERROR_ERRNO("sched_getparam");
        gprio_clean();
        return -1;
    }

    state.policy = sched_getscheduler(0);
    if (state.policy == -1) {
        PRINT_ERROR_ERRNO("sched_getscheduler");
        gprio_clean();
        return -1;
    }

    // Set highest priority & scheduler policy.

    struct sched_param p = { .sched_priority = sched_get_priority_max(SCHED_FIFO) };
    if (sched_setscheduler(0, SCHED_FIFO, &p) < 0) {
        PRINT_ERROR_ERRNO("sched_setscheduler");
        gprio_clean();
        return -1;
    }

    return 0;
}
