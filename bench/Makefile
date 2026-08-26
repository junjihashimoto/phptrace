ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

CFLAGS ?= -O2 -g -Wall -Wextra

all: percall.bpf.o percall_load

# clang -target bpf doesn't search the multiarch include dir Debian uses
MULTIARCH := $(shell $(CC) -print-multiarch)

percall.bpf.o: percall.bpf.c
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -I/usr/include/$(MULTIARCH) -c $< -o $@

percall_load: percall_load.c
	$(CC) $(CFLAGS) percall_load.c -o $@ -lbpf -lelf -lz

clean:
	rm -f percall.bpf.o percall_load
