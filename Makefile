OBJECTS = cpu.o msr.o prctl.o seccomp.o ssbd.o
HEADERS = $(OBJECTS:.o=.h)

.PHONY: check clean

check-ssbd: check_ssbd.c $(OBJECTS) $(HEADERS)
	$(CC) -o check-ssbd $(OBJECTS) check_ssbd.c

$(OBJECTS): %.o : %.c $(HEADERS)
	$(CC) -c -o $@ $<

check: check-ssbd
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd $(OBJECTS)
