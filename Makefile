.PHONY: check clean

check-ssbd:
	$(CC) -o check-ssbd check_ssbd.c

check: check-ssbd
	@./test.sh && echo PASS

clean:
	rm -f check-ssbd
