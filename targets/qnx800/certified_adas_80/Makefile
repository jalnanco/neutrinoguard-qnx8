# QNX SDP 8.0 Cross-Compilation Makefile (`aarch64le` / `x86_64`) + Host Syntax Check
TARGET_ARCH ?= aarch64le
QCC_PROFILE ?= gcc_nto$(TARGET_ARCH)
QCC         ?= qcc -V$(QCC_PROFILE)
QNX_CFLAGS  := -std=c11 -Wall -Wextra -Werror -O2 -D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -fstack-protector-strong

ifeq ($(TARGET_ARCH),aarch64le)
QNX_CFLAGS  += -mbranch-protection=standard
endif

BINS := actuator_ctrl safety_monitor diag_logger

.PHONY: all qnx8 host-check clean

all: qnx8

qnx8:
	@mkdir -p build/$(TARGET_ARCH)
	$(QCC) $(QNX_CFLAGS) actuator_ctrl.c -o build/$(TARGET_ARCH)/actuator_ctrl
	$(QCC) $(QNX_CFLAGS) safety_monitor.c -o build/$(TARGET_ARCH)/safety_monitor
	$(QCC) $(QNX_CFLAGS) diag_logger.c -o build/$(TARGET_ARCH)/diag_logger

host-check:
	@mkdir -p build/host
	$(CC) -std=c11 -Wall -Wextra -Werror -O2 actuator_ctrl.c -o build/host/actuator_ctrl
	$(CC) -std=c11 -Wall -Wextra -Werror -O2 safety_monitor.c -o build/host/safety_monitor
	$(CC) -std=c11 -Wall -Wextra -Werror -O2 diag_logger.c -o build/host/diag_logger

clean:
	rm -rf build
