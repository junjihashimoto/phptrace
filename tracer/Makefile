ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

CFLAGS ?= -O2 -g -Wall -Wextra

all: phptrace.bpf.o phptracer

# clang -target bpf doesn't search the multiarch include dir Debian uses
MULTIARCH := $(shell $(CC) -print-multiarch)

phptrace.bpf.o: phptrace.bpf.c phptrace.h
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -I/usr/include/$(MULTIARCH) -c $< -o $@

phptracer: main.c phptrace.h offsets_php83.h offsets_php74.h
	$(CC) $(CFLAGS) main.c -o $@ -lbpf -lelf -lz

clean:
	rm -f phptrace.bpf.o phptracer
