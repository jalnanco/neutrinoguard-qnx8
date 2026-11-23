/*
 * Certified QNX OS 8.0 ADAS Diagnostic Ring-Buffer Logger
 * - Pre-allocated lock-free ring slab + mlockall(MCL_CURRENT | MCL_FUTURE)
 * - Pure sink node in IPC DAG (never blocks upstream real-time actuators)
 */
#include "include/adas_ipc.h"

#define RING_SLOTS 256U

typedef struct {
    uint32_t seq_ring[RING_SLOTS];
    uint32_t write_idx;
} diag_ring_t;

static diag_ring_t g_ring;

int main(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        return 1;
    }

    struct sched_param sp;
    sp.sched_priority = 22;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    procmgr_ability(
        0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_PATHSPACE,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_PATHSPACE,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_MEM_LOCK,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_LOCK  | PROCMGR_AID_MEM_LOCK,
        PROCMGR_AID_EOL
    );
    drop_service_uid(1003);

    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK);
    dispatch_t *dpp = dispatch_create_channel(chid, 0);
    name_attach_t *attach = name_attach(dpp, "diag_logger", 0);

    uint64_t pulse_buf = 0;
    for (;;) {
        rcvid_t rcvid = MsgReceive(attach->chid, &pulse_buf, sizeof(pulse_buf), NULL);
        if (rcvid < 0) {
            break;
        }
        g_ring.seq_ring[g_ring.write_idx & (RING_SLOTS - 1U)] = (uint32_t)pulse_buf;
        g_ring.write_idx++;
        if (rcvid > 0) {
            MsgReply(rcvid, 0, &g_ring.write_idx, sizeof(g_ring.write_idx));
        }
    }
    return 0;
}
