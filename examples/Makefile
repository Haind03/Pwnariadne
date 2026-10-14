# Build the deliberately-unsafe demo targets for testing Pwnariadne.
# Built with classic (unsafe) settings so the sinks survive into the binary.
CC ?= gcc
CFLAGS ?= -fno-stack-protector -no-pie -O0 -g -w

all: vuln_demo heap_demo fptr_demo seccomp_demo

vuln_demo: vuln_demo.c
	$(CC) $(CFLAGS) -o $@ $<

heap_demo: heap_demo.c
	$(CC) $(CFLAGS) -o $@ $<

fptr_demo: fptr_demo.c
	$(CC) $(CFLAGS) -o $@ $<

seccomp_demo: seccomp_demo.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f vuln_demo heap_demo fptr_demo seccomp_demo

.PHONY: all clean
