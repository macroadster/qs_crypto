#!/usr/bin/env bash
# Optional external batteries when Docker images exist.
# Does not fail the research tree if Docker is offline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="${ROOT}/research/prng_quality/out"
mkdir -p "$OUT"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not available — skip external suites"
  exit 0
fi

if [ ! -f "$OUT/sut_a_spinprng.bin" ]; then
  echo "missing $OUT/sut_a_spinprng.bin — run prng_quality harness first"
  exit 1
fi

if docker image inspect qs-crypto-rng-tests >/dev/null 2>&1; then
  echo "=== dieharder on SUT-A (file_input; prefer larger streams) ==="
  docker run --rm \
    -v "${OUT}:/data:ro" \
    -v "${OUT}:/out" \
    qs-crypto-rng-tests \
    dieharder -a -g 201 -f /data/sut_a_spinprng.bin | tee "${OUT}/sut_a_dieharder.txt"
else
  echo "image qs-crypto-rng-tests missing — build with:"
  echo "  docker build -t qs-crypto-rng-tests ${ROOT}/scripts/rng_docker"
fi

if docker image inspect qs-crypto-testu01 >/dev/null 2>&1; then
  echo "=== BigCrush streaming (long; host SpinPrng → container) ==="
  echo "Use: ${ROOT}/scripts/testu01/run_bigcrush.sh"
else
  echo "image qs-crypto-testu01 missing — build with:"
  echo "  docker build -t qs-crypto-testu01 ${ROOT}/scripts/testu01"
fi
