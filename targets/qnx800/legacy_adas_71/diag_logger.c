/*
 * Legacy QNX SDP 7.1 Diagnostic Logger
 * Closes a fatal 3-node synchronous MsgSend deadlock cycle back into actuator_ctrl!
 */
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>

int main(void) {
    struct sched_param sp;
    sp.sched_priority = 18;
    pthread_setschedparam(pthread_self(), SCHED_RR, &sp);

    name_attach_t *attach = name_attach(NULL, "diag_logger", 0);
    int act_coid = name_open("actuator_ctrl", 0);

    uint64_t payload = 0;
    uint64_t snapshot = 0;

    while (1) {
        int rcvid = MsgReceive(attach->chid, &payload, sizeof(payload), NULL);
        if (rcvid > 0) {
            /* HAZARD [QNX8-RT-004]: Dynamic heap allocation in RT message loop without mlockall() */
            char *record = (char *)malloc(256);

            /* HAZARD [QNX8-RT-006]: Synchronous back-edge diag_logger -> actuator_ctrl closes cycle! */
            MsgSend(act_coid, &payload, sizeof(payload), &snapshot, sizeof(snapshot));

            if (record != NULL) {
                free(record);
            }
            MsgReply(rcvid, 0, &snapshot, sizeof(snapshot));
        }
    }
    return 0;
}
