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

#include <stdbool.h>
#include <stdio.h>

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "picotls/mbedtls.h"

void ptls_mbedtls_random_bytes(void *buf, size_t len)
{
    static mbedtls_entropy_context entropy; /* entropy pool for seeding PRNG */
    static mbedtls_ctr_drbg_context drbg;   /* pseudo-random generator */
    static bool needs_init = true;

    if (needs_init) {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);

        /* seed the PRNG using the entropy pool */
        int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, 0, 0);
        if (ret != 0) {
            fprintf(stderr, "mbedtls_ctr_drbg_seed() failed w/code: %d\n", ret);
            abort();
        }
        needs_init = false;
    }

    int ret = mbedtls_ctr_drbg_random(&drbg, buf, len);
    if (ret != 0) {
        fprintf(stderr, "mbedtls_ctr_drbg_random() failed w/code: %d\n", ret);
        abort();
    }
}
