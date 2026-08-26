ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
MULTIARCH := $(shell $(CC) -print-multiarch)

all: target probe.bpf.o probe_map.bpf.o probe_read.bpf.o probe_full.bpf.o probe_gated.bpf.o probe_heavy.bpf.o load

target: target.c
	$(CC) -O2 -g -fno-omit-frame-pointer target.c -o target

%.bpf.o: %.bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(MULTIARCH) -c $< -o $@

load: load.c
	$(CC) -O2 -g load.c -o load -lbpf -lelf -lz

clean:
	rm -f target probe.bpf.o load
