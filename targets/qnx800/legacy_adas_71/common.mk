# Legacy QNX SDP 7.1 common.mk with 32-bit target and obsolete io-sock VPATH
CC = qcc -Vgcc_ntoarmv7le
EXTRA_INCVPATH += $(QNX_TARGET)/usr/include/io-sock
LIBVPATH += $(QNX_TARGET)/armle-v7/usr/lib/libsocket
CFLAGS += -Wall -O2
