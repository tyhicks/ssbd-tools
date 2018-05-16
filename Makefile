.PHONY: all clean

all:
	$(CC) -o check-ssbd check_ssbd.c

clean:
	rm -f check-ssbd
