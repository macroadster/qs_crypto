/*
 * TestU01 BigCrush over a continuous binary stream on stdin.
 *
 * Finite files are too small for BigCrush (first MultinomialOver alone
 * consumes >1 GiB). Pipe an on-the-fly SpinPrng stream instead:
 *
 *   cargo run --release --bin stats -- --megabytes 200000 --output - \
 *     | docker run --rm -i --entrypoint bigcrush_stream qs-crypto-testu01
 *
 * Expect multi-hour run; SpinPrng throughput (~0.8 MiB/s release on host) dominates.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "unif01.h"
#include "bbattery.h"

static FILE *g_in;

/* Big-endian 32-bit words from the byte stream (arbitrary; only randomness matters). */
static unsigned long spinprng_bits(void)
{
    unsigned char b[4];
    size_t n = fread(b, 1, 4, g_in);
    if (n != 4) {
        fprintf(stderr, "\nbigcrush_stream: EOF/short read after feeding BigCrush "
                        "(need a longer --megabytes stream)\n");
        exit(2);
    }
    return ((unsigned long)b[0] << 24) | ((unsigned long)b[1] << 16)
         | ((unsigned long)b[2] << 8) | (unsigned long)b[3];
}

int main(void)
{
    g_in = stdin;
    if (g_in == NULL) {
        fprintf(stderr, "stdin unavailable\n");
        return 1;
    }

    printf("=== TestU01 BigCrush — QS-Crypto SpinPrng (stdin stream) ===\n\n");
    fflush(stdout);

    unif01_Gen *gen = unif01_CreateExternGenBits("SpinPrng_QS256_stdin", spinprng_bits);
    if (gen == NULL) {
        fprintf(stderr, "unif01_CreateExternGenBits failed\n");
        return 1;
    }

    bbattery_BigCrush(gen);

    unif01_DeleteExternGenBits(gen);
    printf("\n=== BigCrush complete ===\n");
    return 0;
}
