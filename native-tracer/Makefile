ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CFLAGS ?= -O2 -g -Wall -Wextra
MULTIARCH := $(shell $(CC) -print-multiarch)

all: native.bpf.o native

native.bpf.o: native.bpf.c native.h
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -I/usr/include/$(MULTIARCH) -c $< -o $@

native: native.c native.h
	$(CC) $(CFLAGS) native.c -o $@ -lbpf -lelf -lz -lstdc++

clean:
	rm -f native.bpf.o native
