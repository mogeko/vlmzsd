# Builds the reference-vector dump tool from the C reference implementation.
# This is a one-time bootstrap helper — NOT part of the Zig build system.

CC ?= cc
CFLAGS ?= -O2
CPPFLAGS = -Ivlmcsd-src

OBJS = crypto.o crypto_internal.o endian.o dump_vectors.o

all: dump_vectors

dump_vectors: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

crypto.o: vlmcsd-src/crypto.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ vlmcsd-src/crypto.c

crypto_internal.o: vlmcsd-src/crypto_internal.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ vlmcsd-src/crypto_internal.c

endian.o: vlmcsd-src/endian.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ vlmcsd-src/endian.c

dump_vectors.o: dump_vectors.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ dump_vectors.c

clean:
	rm -f dump_vectors $(OBJS)

.PHONY: all clean
