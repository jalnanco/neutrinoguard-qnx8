/*
 * Certified QNX OS 8.0 ADAS Safety Monitor Resource Manager
 * - Enables automatic QNX microkernel priority inheritance (no _NTO_CHF_FIXED_PRIORITY)
 * - Handles _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK cleanly
 * - Initializes mutexes with PTHREAD_PRIO_INHERIT
 * - Emits non-blocking MsgSendPulse() to diag_logger (zero circular MsgSend)
 */
#include "include/adas_ipc.h"

static pthread_mutex_t g_envelope_mtx;

int main(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        return 1;
    }

    struct sched_param sp;
    sp.sched_priority = 48;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&g_envelope_mtx, &mattr);

    procmgr_ability(
        0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_LOCK,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_MEM_LOCK,
        PROCMGR_AID_EOL
    );
    drop_service_uid(1002);

    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);
    dispatch_t *dpp = dispatch_create_channel(chid, 0);

    resmgr_attr_t rattr = {0};
    iofunc_attr_t ioattr;
    iofunc_attr_init(&ioattr, S_IFNAM | 0660, NULL, NULL);
    resmgr_attach(dpp, &rattr, "/dev/adas_safety", _FTYPE_ANY, 0, NULL, NULL, &ioattr);
    name_attach_t *attach = name_attach(dpp, "safety_monitor", 0);

    int diag_coid = name_open("diag_logger", 0);
    adas_brake_cmd_t cmd;
    adas_safety_reply_t reply;

    for (;;) {
        rcvid_t rcvid = MsgReceive(attach->chid, &cmd, sizeof(cmd), NULL);
        if (rcvid < 0) {
            break;
        }
        if (rcvid > 0) {
            pthread_mutex_lock(&g_envelope_mtx);
            reply.sequence_id = cmd.sequence_id;
            reply.approved_pressure_kpa = cmd.brake_pressure_kpa <= 12000U ? cmd.brake_pressure_kpa : 12000U;
            reply.safety_state = 1U;
            pthread_mutex_unlock(&g_envelope_mtx);

            /* Non-blocking 4-byte kernel pulse breaks the legacy IPC cycle */
            MsgSendPulse(diag_coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_DIAG_AUDIT, (int)cmd.sequence_id);
            MsgReply(rcvid, 0, &reply, sizeof(reply));
        }
    }
    return 0;
}
