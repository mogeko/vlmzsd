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

    // Non-block-aligned v4 MAC lengths (ISO 9797-1 method 2 padding).
    {
        BYTE msg[64];
        memset(msg, 0, sizeof(msg));
        AesCmacV4(msg, 20, mac);
        dump_hex("cmac_v4_zeros_20", mac, 16);
    }
    {
        BYTE msg[64];
        memset(msg, 0, sizeof(msg));
        AesCmacV4(msg, 34, mac);
        dump_hex("cmac_v4_zeros_34", mac, 16);
    }

    // v6 non-standard AES key schedule (IsV6 = TRUE) applied to a zero block.
    {
        AesInitKey(&ctx, AesKeyV6, TRUE, 16);
        memset(mac, 0, 16);
        AesEncryptBlock(&ctx, mac);
        dump_hex("aes_v6_encrypt_zero_block", mac, 16);
    }

    // HMAC-SHA256 with a 16-byte key over a fresh 32-byte zero buffer.
    {
        BYTE key[16];
        BYTE data[32];
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        Sha256Hmac(key, data, 32, hmac);
        dump_hex("hmac_sha256_zeros_32", hmac, 32);
    }

    // v5 (standard 128-bit AES, IsV6 = FALSE) applied to a zero block.
    {
        AesInitKey(&ctx, AesKeyV5, FALSE, 16);
        memset(mac, 0, 16);
        AesEncryptBlock(&ctx, mac);
        dump_hex("aes_v5_encrypt_zero_block", mac, 16);
    }

    // v6 decrypt: decrypt the known ciphertext of the zero block back to zero.
    {
        AesInitKey(&ctx, AesKeyV6, TRUE, 16);
        memset(mac, 0, 16);
        AesEncryptBlock(&ctx, mac);
        AesDecryptBlock(&ctx, mac);
        dump_hex("aes_v6_decrypt_zero_block", mac, 16);
    }

    // v6 CBC encrypt: zero IV, 32 zero bytes (padded to 48) — in place.
    {
        BYTE data[64];
        BYTE iv[16];
        size_t len;
        AesInitKey(&ctx, AesKeyV6, TRUE, 16);
        memset(data, 0, sizeof(data));
        memset(iv, 0, sizeof(iv));
        len = 32;
        AesEncryptCbc(&ctx, iv, data, &len);
        dump_hex("aes_cbc_encrypt_zeros32_v6", data, len);
    }

    // v6 CBC decrypt round-trip: decrypt the ciphertext above (in place).
    {
        BYTE data[64];
        BYTE iv[16];
        size_t len;
        AesInitKey(&ctx, AesKeyV6, TRUE, 16);
        memset(data, 0, sizeof(data));
        memset(iv, 0, sizeof(iv));
        len = 32;
        AesEncryptCbc(&ctx, iv, data, &len);
        AesDecryptCbc(&ctx, iv, data, len);
        dump_hex("aes_cbc_decrypt_zeros32_v6", data, len);
    }

    return 0;
}
