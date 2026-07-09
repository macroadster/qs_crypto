/*
 * BigCrush wrapper for QS-Crypto SpinPrng output.
 *
 * Two modes of operation:
 *
 *   1. FILE MODE (pre-generated data):
 *        cargo run --release --bin stats -- --megabytes 1024 --output spinprng_bigcrush.bin
 *        ./bigcrush_wrapper spinprng_bigcrush.bin
 *
 *   2. PIPE MODE (live streaming — recommended, no large file needed):
 *        cargo run --release --bin stats -- --megabytes 4096 --output /dev/stdout | ./bigcrush_wrapper -
 *
 *      At ~250 MiB/s generation speed, the SpinPrng easily sustains
 *      BigCrush's ~74 MiB/s consumption rate, so this finishes within
 *      the same ~4 hours as file mode without requiring disk space.
 *
 * Compile (requires TestU01 installed):
 *   gcc -O2 -o bigcrush_wrapper bigcrush_wrapper.c -ltestu01 -lprobdist -lmylib -lm
 *
 * BigCrush runs 160 tests and takes approximately 4 hours on modern hardware.
 * Results are printed to stdout — redirect to a file for the report.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* TestU01 headers */
#include "unif01.h"
#include "bbattery.h"
#include "ufile.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary-file | ->\n", argv[0]);
        fprintf(stderr, "\n  File mode (pre-generated):\n");
        fprintf(stderr, "    cargo run --release --bin stats -- --megabytes 1024 --output spinprng_bigcrush.bin\n");
        fprintf(stderr, "    %s spinprng_bigcrush.bin\n", argv[0]);
        fprintf(stderr, "\n  Pipe mode (live, no large file needed, recommended):\n");
        fprintf(stderr, "    cargo run --release --bin stats -- --megabytes 4096 --output /dev/stdout 2>/dev/null | %s -\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];

    printf("=== TestU01 BigCrush — QS-Crypto SpinPrng ===\n\n");
    printf("Input file: %s\n\n", filename);
    fflush(stdout);

    /* nbuf is the read buffer size in bytes (not the file size). Keep modest. */
    unif01_Gen *gen = ufile_CreateReadBin(filename, 16L * 1024L * 1024L);

    if (gen == NULL) {
        fprintf(stderr, "Error: could not open %s\n", filename);
        return 1;
    }

    /* Run BigCrush (160 tests) */
    bbattery_BigCrush(gen);

    ufile_DeleteReadBin(gen);

    printf("\n=== BigCrush complete ===\n");
    return 0;
}