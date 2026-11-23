/*
 * Surgical Robot Force-Feedback Telemetry Bus
 */
#include <stdint.h>
#include <sched.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>

int main(void) {
    struct sched_param sp;
    sp.sched_priority = 28;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    /* Missing _NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK and retains UID 0 */
    int chid = ChannelCreate(0);
    name_attach_t *attach = name_attach(NULL, "telemetry_bus", 0);
    int servo_coid = name_open("joint_servo", 0);

    uint64_t pkt = 0;
    while (1) {
        rcvid_t rcvid = MsgReceive(chid, &pkt, sizeof(pkt), NULL);
        if (rcvid > 0) {
            MsgSendPulse(servo_coid, 28, 0x11, 1);
            MsgReply(rcvid, 0, &pkt, sizeof(pkt));
        }
        (void)attach;
    }
    return 0;
}
