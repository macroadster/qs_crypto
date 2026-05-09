/*
 * BigCrush wrapper for QS-Crypto SpinPrng output.
 *
 * Reads a binary file produced by:
 *   cargo run --release --bin stats -- --megabytes 1024 --output spinprng_bigcrush.bin
 *
 * Compile (requires TestU01 installed):
 *   gcc -O2 -o bigcrush_wrapper bigcrush_wrapper.c -ltestu01 -lprobdist -lmylib -lm
 *
 * Run:
 *   ./bigcrush_wrapper spinprng_bigcrush.bin
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
        fprintf(stderr, "Usage: %s <binary-file>\n", argv[0]);
        fprintf(stderr, "  Generate the file with:\n");
        fprintf(stderr, "    cargo run --release --bin stats -- --megabytes 1024 --output spinprng_bigcrush.bin\n");
        return 1;
    }

    const char *filename = argv[1];

    printf("=== TestU01 BigCrush — QS-Crypto SpinPrng ===\n\n");
    printf("Input file: %s\n\n", filename);

    /* Create a generator that reads from the binary file */
    unif01_Gen *gen = ufile_CreateReadBin(filename, (1024ULL * 1024 * 1024));

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