/*
 * Shared QNX OS 8.0 (SDP 8.0) Real-Time IPC Contracts & Host Syntax Verification Shim
 * Compiles natively under QNX SDP 8.0 (`qcc -Vgcc_ntoaarch64le` / `qcc -Vgcc_ntox86_64`)
 * and supports host syntax/CI smoke verification on macOS/Linux when `__QNX__` is absent.
 */
#ifndef ADAS_IPC_H
#define ADAS_IPC_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>

#ifdef __QNX__
#include <sys/neutrino.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/procmgr.h>
#include <sys/siginfo.h>
#else
/* Host CI syntax-verification definitions matching QNX SDP 8.0 64-bit signatures */
typedef int64_t rcvid_t;
typedef struct _pulse {
    uint16_t type;
    uint16_t subtype;
    int8_t code;
    uint8_t zero[3];
    union {
        int32_t sival_int;
        void *sival_ptr;
    } value;
    int32_t scoid;
} struct_pulse_t;

typedef struct {
    int chid;
} name_attach_t;

typedef void dispatch_t;
typedef struct { int reserved; } resmgr_attr_t;
typedef struct { int mode; } iofunc_attr_t;
struct sigevent { int sigev_notify; int sigev_coid; int sigev_priority; int sigev_code; int sigev_value; };

#define _NTO_CHF_DISCONNECT 0x0002U
#define _NTO_CHF_UNBLOCK    0x0001U
#define _NTO_TCTL_IO_LEVEL  19
#define _NTO_IO_LEVEL_1     1
#define _NTO_INTR_FLAGS_TRK_MSK 0x08U
#define _FTYPE_ANY          0
#define S_IFNAM             0050000
#define SIGEV_PULSE_PRIO_INHERIT (-1)
#define _PULSE_CODE_MINAVAIL 0

#define PROCMGR_ADN_NONROOT 0x00020000U
#define PROCMGR_AOP_ALLOW   0x00010000U
#define PROCMGR_AOP_LOCK    0x00800000U
#define PROCMGR_AID_IO      1U
#define PROCMGR_AID_INTERRUPT 2U
#define PROCMGR_AID_PATHSPACE 3U
#define PROCMGR_AID_MEM_LOCK  4U
#define PROCMGR_AID_PRIORITY  5U
#define PROCMGR_AID_EOL     0U

static inline int ThreadCtl(int cmd, void *data) { (void)cmd; (void)data; return 0; }
static inline int InterruptAttachEvent(int intr, const struct sigevent *ev, unsigned flags) {
    (void)intr; (void)ev; (void)flags; return 1;
}
static inline int ChannelCreate(unsigned flags) { (void)flags; return 3; }
static inline dispatch_t *dispatch_create_channel(int chid, unsigned flags) { (void)chid; (void)flags; return (dispatch_t *)0x1; }
static inline void iofunc_attr_init(iofunc_attr_t *a, int m, void *o, void *c) { a->mode = m; (void)o; (void)c; }
static inline int resmgr_attach(dispatch_t *d, resmgr_attr_t *r, const char *p, int t, unsigned f, const void *cf, const void *iof, iofunc_attr_t *a) {
    (void)d; (void)r; (void)p; (void)t; (void)f; (void)cf; (void)iof; (void)a; return 0;
}
static inline name_attach_t *name_attach(dispatch_t *dpp, const char *path, unsigned flags) {
    static name_attach_t na = { 3 }; (void)dpp; (void)path; (void)flags; return &na;
}
static inline int name_open(const char *name, int flags) { (void)name; (void)flags; return 4; }
static inline rcvid_t MsgReceive(int chid, void *msg, size_t bytes, void *info) {
    (void)chid; (void)msg; (void)bytes; (void)info; return -1;
}
static inline int MsgSend(int coid, const void *smsg, size_t sbytes, void *rmsg, size_t rbytes) {
    (void)coid; (void)smsg; (void)sbytes; (void)rmsg; (void)rbytes; return 0;
}
static inline int MsgSendPulse(int coid, int prio, int code, int value) {
    (void)coid; (void)prio; (void)code; (void)value; return 0;
}
static inline int MsgReply(rcvid_t rcvid, int64_t status, const void *msg, size_t size) {
    (void)rcvid; (void)status; (void)msg; (void)size; return 0;
}
static inline int procmgr_ability(int pid, ...) { (void)pid; return 0; }
static inline void SIGEV_INTR_INIT(struct sigevent *e) { e->sigev_notify = 1; }
static inline void SIGEV_PULSE_INIT(struct sigevent *e, int coid, int prio, int code, int val) {
    e->sigev_notify = 4; e->sigev_coid = coid; e->sigev_priority = prio; e->sigev_code = code; e->sigev_value = val;
}
static inline int TimerCreate(clockid_t id, const struct sigevent *ev) { (void)id; (void)ev; return 1; }
static inline int drop_service_uid(uid_t uid) { return setuid(uid); }
#endif

#ifdef __QNX__
static inline int drop_service_uid(uid_t uid) { return setresuid(uid, uid, uid); }
#endif

#define PULSE_CAN_RX_IST    (_PULSE_CODE_MINAVAIL + 1)
#define PULSE_CONTROL_TICK  (_PULSE_CODE_MINAVAIL + 2)
#define PULSE_DIAG_AUDIT    (_PULSE_CODE_MINAVAIL + 3)

typedef struct {
    uint16_t msg_type;
    uint16_t brake_pressure_kpa;
    uint32_t sequence_id;
    uint64_t monotonic_ns;
} adas_brake_cmd_t;

typedef struct {
    uint32_t sequence_id;
    uint16_t approved_pressure_kpa;
    uint16_t safety_state;
} adas_safety_reply_t;

#endif /* ADAS_IPC_H */
