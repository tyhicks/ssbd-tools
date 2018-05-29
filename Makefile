.PHONY: check clean

check-ssbd: check_ssbd.c
	$(CC) -o check-ssbd check_ssbd.c

check: check-ssbd
	@modprobe msr
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd
