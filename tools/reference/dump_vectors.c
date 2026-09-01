// One-time reference-vector dump for the vlmzsd Zig migration.
//
// This is a BOOTSTRAP tool, not part of the Zig build. It links against the C
// reference objects produced by `make` (build/crypto.o, build/crypto_internal.o,
// build/endian.o) and prints byte-exact outputs of the vlmcsd crypto functions.
//
// Build (run from the repository root, requires the C objects built by `make`):
//   gcc -Isrc -o tools/reference/dump_vectors tools/reference/dump_vectors.c \
//       build/crypto.o build/crypto_internal.o build/endian.o
//   ./tools/reference/dump_vectors
//
// The printed hex strings are committed as fixtures under testdata/crypto/.

#include <stdio.h>
#include <string.h>
#include "config.h"
#include "types.h"
#include "crypto.h"

static void dump_hex(const char *label, const BYTE *data, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    BYTE msg[64];
    BYTE out[32];
    BYTE key[16];
    AesCtx ctx;

    memset(msg, 0, sizeof(msg));
    memset(key, 0, sizeof(key));

    // v4 MAC: AesCmacV4 over zero-filled messages of two lengths.
    AesCmacV4(msg, 32, out);
    dump_hex("cmac_v4_zeros_32", out, 16);

    AesCmacV4(msg, 16, out);
    dump_hex("cmac_v4_zeros_16", out, 16);

    // v6 non-standard AES key schedule (IsV6 = TRUE) applied to a zero block.
    AesInitKey(&ctx, AesKeyV6, TRUE, 16);
    memset(out, 0, 16);
    AesEncryptBlock(&ctx, out);
    dump_hex("aes_v6_encrypt_zero_block", out, 16);

    // HMAC-SHA256 with a 16-byte key (key length is hardcoded in Sha256Hmac).
    Sha256Hmac(key, msg, 32, out);
    dump_hex("hmac_sha256_zeros_32", out, 32);

    return 0;
}
