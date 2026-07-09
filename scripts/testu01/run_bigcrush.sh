#!/usr/bin/env bash
# Pipe continuous SpinPrng bytes into TestU01 BigCrush (Docker).
# Finite 1 GiB files are insufficient for BigCrush's first MultinomialOver alone.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/benches/reports/v0.3/results/bigcrush_results.txt"
# Upper bound on stream size (MiB). BigCrush typically finishes well under this
# if generation keeps up; increase if you hit EOF (exit 2 from bigcrush_stream).
MEGABYTES="${BIGCRUSH_MEGABYTES:-200000}"
mkdir -p "$(dirname "$OUT")"

if ! docker image inspect qs-crypto-testu01 >/dev/null 2>&1; then
  docker build -t qs-crypto-testu01 "${ROOT}/scripts/testu01"
fi

echo "Streaming SpinPrng (up to ${MEGABYTES} MiB) → BigCrush (Docker)"
echo "Results → $OUT"
echo "Note: host SpinPrng ~0.8 MiB/s (release); wall time can still be many hours."

cd "$ROOT"
# stderr from stats and docker go to terminal; stdout binary → docker stdin
# BigCrush text results from container stdout → tee
cargo run --release --bin stats -- --megabytes "$MEGABYTES" --output - 2>"${OUT}.stats.log" \
  | docker run --rm -i \
      --entrypoint bigcrush_stream \
      qs-crypto-testu01 \
  | tee "$OUT"

echo "Done. Results: $OUT"
