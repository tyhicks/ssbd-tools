.PHONY: all clean

all:
	$(CC) -o read-ssb read_ssb.c

clean:
	rm -f read-ssb
