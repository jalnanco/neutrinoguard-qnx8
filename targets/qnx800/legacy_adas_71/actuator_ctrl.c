/*
 * Legacy QNX SDP 7.1 ADAS Emergency Braking Actuator Controller
 * Deliberately preserves common QNX 7.1 -> 8.0 migration & real-time hazards
 * for NeutrinoGuard 8 verification.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>

typedef struct {
    uint16_t type;
    uint16_t brake_pressure_kpa;
    uint32_t seq;
} actuator_msg_t;

static volatile uint32_t g_irq_frames = 0;

/* HAZARD [QNX8-RT-001]: Kernel-mode ISR calls malloc() and printf() */
const struct sigevent *can_rx_isr(void *area, int id) {
    (void)area;
    (void)id;
    uint8_t *rx_copy = (uint8_t *)malloc(64);
    if (rx_copy != NULL) {
        g_irq_frames++;
        free(rx_copy);
    }
    printf("CAN IRQ frame=%u\n", g_irq_frames);
    return NULL;
}

int main(void) {
    struct sched_param sp;
    sp.sched_priority = 63;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    /* HAZARD [QNX8-MIG-004]: Blanket legacy _NTO_TCTL_IO instead of _NTO_TCTL_IO_LEVEL */
    ThreadCtl(_NTO_TCTL_IO, 0);

    /* Attach raw kernel ISR on CAN controller vector 42 */
    InterruptAttach(42, can_rx_isr, NULL, 0, 0);

    /* HAZARD [QNX8-SEC-001]: Attaches public name without dropping root via procmgr_ability/setresuid */
    name_attach_t *attach = name_attach(NULL, "actuator_ctrl", 0);
    int safety_coid = name_open("safety_monitor", 0);

    actuator_msg_t msg;
    actuator_msg_t reply;

    while (1) {
        /* HAZARD [QNX8-MIG-006]: Narrow 32-bit int used instead of 64-bit rcvid_t */
        int rcvid = MsgReceive(attach->chid, &msg, sizeof(msg), NULL);
        if (rcvid > 0) {
            /* Forward synchronous validation request to safety_monitor */
            MsgSend(safety_coid, &msg, sizeof(msg), &reply, sizeof(reply));
            MsgReply(rcvid, 0, &reply, sizeof(reply));
        }
    }
    return 0;
}
