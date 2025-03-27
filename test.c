 /*********************************************************************
 * Copyright (c) 2016 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or https://opensource.org/licenses/mit-license.php.   *
 **********************************************************************/

#include "ctaes.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef struct {
    int keysize;
    const char* key;
    const char* plain;
    const char* cipher;
} ctaes_test;

typedef struct {
    int keysize;
    const char* key;
    const char* iv;
    const char* plain;
    const char* cipher;
} ctaes_cbc_test;

static const ctaes_test ctaes_tests[] = {
    /* AES test vectors from FIPS 197. */
    {128, "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
    {192, "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"},
    {256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},

    /* AES-ECB test vectors from NIST sp800-38a. */
    {128, "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
    {128, "2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"},
    {128, "2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"},
    {128, "2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"},
    {192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"},
    {192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef"},
    {192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e"},
    {192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e"},
    {256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"},
    {256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"},
    {256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"},
    {256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"}
};

static const ctaes_cbc_test ctaes_cbc_tests[] = {
    /* AES-CBC test vectors from NIST sp800-38a. */
    {
        // Full block length will pad 1 more block
        128, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "a12b0386d815a2c18e9c23b63a7adbf2fd5576ec89b64bef8fff20c67a2db525d6ddfa8efd7b0fcd869ffe84564e603e6df965ae0dc86e097bdf29bfaa45cd57718fb6e84747912749339489f2c17c4d"
    },
    {
        // Incomplete block length pad will pad the remaining bytes to fill block
        128, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b41",
        "a12b0386d815a2c18e9c23b63a7adbf2fd5576ec89b64bef8fff20c67a2db525d6ddfa8efd7b0fcd869ffe84564e603e3501ddd9be60093899819bbc115cfe86"
    },
    {
        // Full block length will pad 1 more block
        192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "17701a9d29c91a94ceed723c34e87abe1c96845ca8b7e8586dfef2fa6bed24098a52cee8d76db67bfde21553d31c2833f77eb59500ac4903bc7076b18465d0ea7e38ba13918e47c316e53ee336370345"
    },
    {
        // Incomplete block length pad will pad the remaining bytes to fill block
        192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b",
        "17701a9d29c91a94ceed723c34e87abe1c96845ca8b7e8586dfef2fa6bed24098a52cee8d76db67bfde21553d31c28339ad0a856f760c64a6bbb3df2dbecdb53"
    },
    {
        // Full block length will pad 1 more block
        256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461164e1f6488d14e7407e98486d3da86f0"
    },
    {
        // Incomplete block length pad will pad the remaining bytes to fill block
        256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd68d99fefe25debc6c0b1eedaac5e98e7e"
    },
    /* AES-CBC padded test vector randomly generated. */
    {
        128, "d2e4c2c3b3c1fe4878a7bf99807ffe2f", "14e7903c078a28514885abac58618a30",
        "5468697320697320612036332d62797465206c6f6e6720706c61696e74657874206578616d706c6520666f72204145532d434243206d6f6465212121",
        "35866e380595f69503f3700004d2e57a732522827550158b0e64ee9307d8d58477699f0706f33690aed4147987f9ab8485611ba9662bf2e41aefa170810f625d"
    }
};

static void from_hex(unsigned char* data, int len, const char* hex) {
    int p;
    for (p = 0; p < len; p++) {
        int v = 0;
        int n;
        for (n = 0; n < 2; n++) {
            assert((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f'));
            if (*hex >= '0' && *hex <= '9') {
                v |= (*hex - '0') << (4 * (1 - n));
            } else {
                v |= (*hex - 'a' + 10) << (4 * (1 - n));
            }
            hex++;
        }
        *(data++) = v;
    }
    assert(*hex == 0);
}

int main(void) {
    int i;
    int fail = 0;
    for (i = 0; i < sizeof(ctaes_tests) / sizeof(ctaes_tests[0]); i++) {
        unsigned char key[32], plain[16], cipher[16], ciphered[16], deciphered[16];
        const ctaes_test* test = &ctaes_tests[i];
        assert(test->keysize == 128 || test->keysize == 192 || test->keysize == 256);
        from_hex(plain, 16, test->plain);
        from_hex(cipher, 16, test->cipher);
        switch (test->keysize) {
            case 128: {
                AES128_ctx ctx;
                from_hex(key, 16, test->key);
                AES128_init(&ctx, key);
                AES128_encrypt(&ctx, 1, ciphered, plain);
                AES128_decrypt(&ctx, 1, deciphered, cipher);
                break;
            }
            case 192: {
                AES192_ctx ctx;
                from_hex(key, 24, test->key);
                AES192_init(&ctx, key);
                AES192_encrypt(&ctx, 1, ciphered, plain);
                AES192_decrypt(&ctx, 1, deciphered, cipher);
                break;
            }
            case 256: {
                AES256_ctx ctx;
                from_hex(key, 32, test->key);
                AES256_init(&ctx, key);
                AES256_encrypt(&ctx, 1, ciphered, plain);
                AES256_decrypt(&ctx, 1, deciphered, cipher);
                break;
            }
        }
        if (memcmp(cipher, ciphered, 16)) {
            fprintf(stderr, "E(key=\"%s\", plain=\"%s\") != \"%s\"\n", test->key, test->plain, test->cipher);
            fail++;
        }
        if (memcmp(plain, deciphered, 16)) {
            fprintf(stderr, "D(key=\"%s\", cipher=\"%s\") != \"%s\"\n", test->key, test->cipher, test->plain);
            fail++;
        }
    }
    for (i = 0; i < sizeof(ctaes_cbc_tests) / sizeof(ctaes_cbc_tests[0]); i++) {
        // Define AES block size (16 bytes for AES).
        const int block_size = 16;

        // Retrieve the test case.
        const ctaes_cbc_test* test = &ctaes_cbc_tests[i];

        // Compute plaintext length (hex string length divided by 2).
        const int plain_len = strlen(test->plain) / 2;

        // Compute the padded plaintext length for PKCS#7.
        // If plaintext is already a multiple of block_size, an extra block is needed.
        const int padded_plain_len = (plain_len % block_size == 0) 
                                    ? (plain_len + block_size) 
                                    : (plain_len + (block_size - (plain_len % block_size)));

        // Compute the number of AES blocks.
        const int blocks = padded_plain_len / block_size;

        // Compute ciphertext length (hex string length divided by 2).
        const int cipher_len = strlen(test->cipher) / 2;

        // Allocate buffers for encryption/decryption.
        unsigned char key[32];                      // Key buffer (up to 256-bit keys, i.e., 32 bytes).
        unsigned char iv[block_size];               // Initialization vector (IV).
        unsigned char plain[plain_len];             // Buffer to store original plaintext.
        unsigned char cipher[cipher_len];           // Expected ciphertext.
        unsigned char ciphered[padded_plain_len];   // Encrypted ciphertext (including padding).
        unsigned char deciphered[padded_plain_len]; // Decrypted plaintext (including padding).

        // Ensure key size is valid (AES supports only 128, 192, or 256 bits).
        assert(test->keysize == 128 || test->keysize == 192 || test->keysize == 256);

        // Convert hex-encoded test data into byte arrays.
        from_hex(iv, block_size, test->iv);          // Convert IV from hex string to byte array.
        from_hex(plain, plain_len, test->plain);     // Convert plaintext from hex string to byte array.
        from_hex(cipher, cipher_len, test->cipher);  // Convert expected ciphertext from hex string to byte array.

        switch (test->keysize) {
            case 128: {
                AES128_CBC_ctx ctx;
                AES128_CBC_init(&ctx, key, iv, /*cipher_len*/0, plain_len);
                AES128_CBC_encrypt(&ctx, blocks, ciphered, plain);

                // Initialize decryption with the ciphertext length.
                AES128_CBC_init(&ctx, key, iv, ctx.data.ciphertext_len, /*plain_len*/0);
                assert(AES128_CBC_decrypt(&ctx, blocks, deciphered, ciphered));
                assert(ctx.data.plaintext_len == plain_len);
                break;
            }
            case 192: {
                AES192_CBC_ctx ctx;
                AES192_CBC_init(&ctx, key, iv, /*cipher_len*/0, plain_len);
                AES192_CBC_encrypt(&ctx, blocks, ciphered, plain);

                // Initialize decryption with the ciphertext length.
                AES192_CBC_init(&ctx, key, iv, ctx.data.ciphertext_len, /*plain_len*/0);
                assert(AES192_CBC_decrypt(&ctx, blocks, deciphered, ciphered));
                assert(ctx.data.plaintext_len == plain_len);
                break;
            }
            case 256: {
                AES256_CBC_ctx ctx;
                AES256_CBC_init(&ctx, key, iv, /*cipher_len*/0, plain_len);
                AES256_CBC_encrypt(&ctx, blocks, ciphered, plain);

                // Initialize decryption with the ciphertext length.
                AES256_CBC_init(&ctx, key, iv, ctx.data.ciphertext_len, /*plain_len*/0);
                assert(AES256_CBC_decrypt(&ctx, blocks, deciphered, ciphered));
                assert(ctx.data.plaintext_len == plain_len);
                break;
            }
        }
        if (memcmp(cipher, ciphered, cipher_len)) {
            fprintf(stderr, "E(key=\"%s\", plain=\"%s\") != \"%s\"\n", test->key, test->plain, test->cipher);
            fail++;
        }
        if (memcmp(plain, deciphered, plain_len)) {
            fprintf(stderr, "D(key=\"%s\", cipher=\"%s\") != \"%s\"\n", test->key, test->cipher, test->plain);
            fail++;
        }
    }
    if (fail == 0) {
        fprintf(stderr, "All tests successful\n");
    } else {
        fprintf(stderr, "%i tests failed\n", fail);
    }
    return (fail != 0);
}
