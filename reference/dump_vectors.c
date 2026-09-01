// One-time reference-vector dump for the vlmzsd Zig migration.
//
// This is a BOOTSTRAP tool, not part of the Zig build. It compiles and links
// against the C reference implementation in `vlmcsd-src/` (via the Makefile in
// this directory) and prints byte-exact outputs of the vlmcsd crypto functions.
//
// Build and run:
//   make
//   ./dump_vectors
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

// NOTE: AesCmacV4 writes the 0x80 padding INTO its input buffer, so each call
// must use a fresh message buffer.

int main(void) {
    BYTE mac[16];
    BYTE hmac[32];
    AesCtx ctx;

    // v4 MAC: AesCmacV4 over zero-filled messages of two lengths.
    {
        BYTE msg[64];
        memset(msg, 0, sizeof(msg));
        AesCmacV4(msg, 32, mac);
        dump_hex("cmac_v4_zeros_32", mac, 16);
    }
    {
        BYTE msg[64];
        memset(msg, 0, sizeof(msg));
        AesCmacV4(msg, 16, mac);
        dump_hex("cmac_v4_zeros_16", mac, 16);
    }

    // v6 non-standard AES key schedule (IsV6 = TRUE) applied to a zero block.
    AesInitKey(&ctx, AesKeyV6, TRUE, 16);
    memset(mac, 0, 16);
    AesEncryptBlock(&ctx, mac);
    dump_hex("aes_v6_encrypt_zero_block", mac, 16);

    // HMAC-SHA256 with a 16-byte key over a fresh 32-byte zero buffer.
    {
        BYTE key[16];
        BYTE data[32];
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        Sha256Hmac(key, data, 32, hmac);
        dump_hex("hmac_sha256_zeros_32", hmac, 32);
    }

    return 0;
}
