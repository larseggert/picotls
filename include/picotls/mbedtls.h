/*
 * Copyright (c) 2019 Lars Eggert <lars@eggert.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef picotls_mbedtls_h
#define picotls_mbedtls_h

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif

#include "picotls.h"

#define SECP256R1_PRIVATE_KEY_SIZE 32

typedef struct st_ptls_mbedtls_secp256r1sha256_sign_certificate_t {
    ptls_sign_certificate_t super;
    uint8_t key[SECP256R1_PRIVATE_KEY_SIZE];
} ptls_mbedtls_secp256r1sha256_sign_certificate_t;

void ptls_mbedtls_random_bytes(void *buf, size_t len);

extern ptls_key_exchange_algorithm_t ptls_mbedtls_secp256r1, ptls_mbedtls_x25519;
extern ptls_cipher_suite_t ptls_mbedtls_aes128gcmsha256, ptls_mbedtls_aes256gcmsha384, ptls_mbedtls_chacha20poly1305sha256;
extern ptls_cipher_suite_t *ptls_mbedtls_cipher_suites[];

#ifdef __cplusplus
}
#endif

#endif
