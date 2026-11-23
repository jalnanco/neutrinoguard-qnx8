/*
 * Legacy QNX SDP 7.1 ADAS Safety Monitor Resource Manager
 * Exhibits _NTO_CHF_FIXED_PRIORITY priority inversion and discontinued PROCMGR_AID_MEM_GLOBAL.
 */
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/procmgr.h>

static pthread_mutex_t g_envelope_mtx;

int main(void) {
    struct sched_param sp;
    sp.sched_priority = 32;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    /* HAZARD [QNX8-RT-005]: Default NULL attributes omit explicit PTHREAD_PRIO_INHERIT */
    pthread_mutex_init(&g_envelope_mtx, NULL);

    /* HAZARD [QNX8-MIG-003 & QNX8-SEC-002]: Discontinued PROCMGR_AID_MEM_GLOBAL and missing PROCMGR_AOP_LOCK */
    procmgr_ability(0, PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_GLOBAL);

    /* HAZARD [QNX8-RT-002 & QNX8-RT-003]: Disables priority inheritance & omits disconnect/unblock pulses */
    int chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY);
    dispatch_t *dpp = dispatch_create_channel(chid, 0);

    resmgr_attr_t rattr;
    iofunc_attr_t ioattr;
    iofunc_attr_init(&ioattr, S_IFNAM | 0660, 0, 0);
    resmgr_attach(dpp, &rattr, "/dev/adas_safety", _FTYPE_ANY, 0, NULL, NULL, &ioattr);
    name_attach_t *attach = name_attach(dpp, "safety_monitor", 0);

    int diag_coid = name_open("diag_logger", 0);
    uint64_t audit_pkt = 0xA5A50001ULL;
    uint64_t ack = 0;

    while (1) {
        int rcvid = MsgReceive(attach->chid, &audit_pkt, sizeof(audit_pkt), NULL);
        if (rcvid > 0) {
            /* Blocking call down to low-priority diag_logger (part of 3-node IPC cycle) */
            MsgSend(diag_coid, &audit_pkt, sizeof(audit_pkt), &ack, sizeof(ack));
            MsgReply(rcvid, 0, &ack, sizeof(ack));
        }
    }
    return 0;
}
