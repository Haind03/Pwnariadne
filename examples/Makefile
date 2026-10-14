# Build the deliberately-unsafe demo target for testing Pwnariadne.
# Built with classic (unsafe) settings so the sinks survive into the binary.
CC ?= gcc
CFLAGS ?= -fno-stack-protector -no-pie -O0 -g -w

vuln_demo: vuln_demo.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f vuln_demo

.PHONY: clean
