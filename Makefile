.PHONY: check clean

check-ssbd: check_ssbd.c cpu.o msr.o prctl.o seccomp.o ssbd.o
	$(CC) -o check-ssbd cpu.o msr.o prctl.o seccomp.o ssbd.o check_ssbd.c

cpu.o: cpu.c cpu.h
	$(CC) -c -o $@ cpu.c

msr.o: msr.c msr.h
	$(CC) -c -o $@ msr.c

prctl.o: prctl.c prctl.h
	$(CC) -c -o $@ prctl.c

seccomp.o: seccomp.c seccomp.h
	$(CC) -c -o $@ seccomp.c

ssbd.o: ssbd.c ssbd.h
	$(CC) -c -o $@ ssbd.c

check: check-ssbd
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd *.o
