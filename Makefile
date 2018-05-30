CFLAGS = -g -O2 -Wformat -Werror=format-security

OBJECTS = cpu.o msr.o prctl.o seccomp.o ssbd.o
HEADERS = $(OBJECTS:.o=.h)

.PHONY: check clean

check-ssbd: check_ssbd.c $(OBJECTS) $(HEADERS)
	$(CC) $(CFLAGS) -o check-ssbd $(OBJECTS) check_ssbd.c

$(OBJECTS): %.o : %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $<

check: check-ssbd
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd $(OBJECTS)
