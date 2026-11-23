/*
 * Certified QNX OS 8.0 ADAS Emergency Braking Actuator Controller
 * - Pins VMM pages via mlockall(MCL_CURRENT | MCL_FUTURE)
 * - Scopes hardware I/O to _NTO_TCTL_IO_LEVEL + PROCMGR_AID_IO and drops root
 * - Uses InterruptAttachEvent() + TimerCreate(CLOCK_MONOTONIC, &SIGEV_PULSE)
 * - Preserves strict DAG IPC hierarchy (actuator_ctrl -> safety_monitor)
 */
#include "include/adas_ipc.h"

int main(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        return 1;
    }

    struct sched_param sp;
    sp.sched_priority = 63;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    procmgr_ability(
        0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_IO,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_IO,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_INTERRUPT,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_INTERRUPT,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,
        PROCMGR_AID_EOL
    );
    drop_service_uid(1001);

    ThreadCtl(_NTO_TCTL_IO_LEVEL, (void *)_NTO_IO_LEVEL_1);

    struct sigevent intr_ev;
    SIGEV_INTR_INIT(&intr_ev);
    InterruptAttachEvent(42, &intr_ev, _NTO_INTR_FLAGS_TRK_MSK);

    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);
    dispatch_t *dpp = dispatch_create_channel(chid, 0);
    name_attach_t *attach = name_attach(dpp, "actuator_ctrl", 0);
    int safety_coid = name_open("safety_monitor", 0);

    struct sigevent tick_ev;
    SIGEV_PULSE_INIT(&tick_ev, safety_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_CONTROL_TICK, 0);
    TimerCreate(CLOCK_MONOTONIC, &tick_ev);

    adas_brake_cmd_t cmd;
    adas_safety_reply_t reply;

    for (;;) {
        rcvid_t rcvid = MsgReceive(attach->chid, &cmd, sizeof(cmd), NULL);
        if (rcvid < 0) {
            break;
        }
        if (rcvid > 0) {
            MsgSend(safety_coid, &cmd, sizeof(cmd), &reply, sizeof(reply));
            MsgReply(rcvid, 0, &reply, sizeof(reply));
        }
    }
    return 0;
}
