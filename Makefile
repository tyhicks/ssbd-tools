CFLAGS = -g -O2 -Wformat -Werror=format-security

CHECK_OBJECTS = cpu.o msr.o prctl.o seccomp.o ssbd.o
CHECK_HEADERS = $(CHECK_OBJECTS:.o=.h)

EXEC_OBJECTS = msr.o prctl.o seccomp.o ssbd.o
EXEC_HEADERS = $(EXEC_OBJECTS:.o=.h)

.PHONY: all check clean

all: check-ssbd ssbd-exec

check-ssbd: check_ssbd.c $(CHECK_OBJECTS) $(CHECK_HEADERS)
	$(CC) $(CFLAGS) -o check-ssbd $(CHECK_OBJECTS) check_ssbd.c

ssbd-exec: ssbd_exec.c $(EXEC_OBJECTS) $(EXEC_HEADERS)
	$(CC) $(CFLAGS) -o ssbd-exec $(EXEC_OBJECTS) ssbd_exec.c

$(OBJECTS): %.o : %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

check: check-ssbd
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd $(CHECK_OBJECTS)
	rm -f ssbd-exec $(EXEC_OBJECTS)
