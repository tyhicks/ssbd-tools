CFLAGS = -g -O2 -Wformat -Werror=format-security

EXEC_OBJECTS = prctl.o seccomp.o
EXEC_HEADERS = $(EXEC_OBJECTS:.o=.h)

VERIFY_OBJECTS = cpu.o prctl.o ssbd.o
VERIFY_HEADERS = $(VERIFY_OBJECTS:.o=.h)

.PHONY: all check clean

all: ssbd-exec ssbd-verify

ssbd-exec: ssbd_exec.c $(EXEC_OBJECTS) $(EXEC_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(EXEC_OBJECTS) $<

ssbd-verify: ssbd_verify.c $(VERIFY_OBJECTS) $(VERIFY_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(VERIFY_OBJECTS) $<

$(OBJECTS): %.o : %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

check: ssbd-exec ssbd-verify
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f ssbd-exec $(EXEC_OBJECTS)
	rm -f ssbd-verify $(VERIFY_OBJECTS)
