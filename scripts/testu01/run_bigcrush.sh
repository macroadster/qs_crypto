#!/usr/bin/env bash
# Pipe continuous SpinPrng bytes into TestU01 BigCrush (Docker).
# Finite files are insufficient; stream until BigCrush closes stdin.
# Default: unlimited (--megabytes 0). Optional cap: BIGCRUSH_MEGABYTES=N.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/benches/reports/v0.3/results/bigcrush_results.txt"
# 0 = unlimited until Docker/bigcrush closes the pipe (recommended).
MEGABYTES="${BIGCRUSH_MEGABYTES:-0}"
mkdir -p "$(dirname "$OUT")"

if ! docker image inspect qs-crypto-testu01 >/dev/null 2>&1; then
  docker build -t qs-crypto-testu01 "${ROOT}/scripts/testu01"
fi

if [[ "$MEGABYTES" == "0" ]]; then
  echo "Streaming SpinPrng (unlimited until BigCrush exits) → Docker"
else
  echo "Streaming SpinPrng (up to ${MEGABYTES} MiB) → BigCrush (Docker)"
fi
echo "Results → $OUT"
echo "Note: host SpinPrng is fast post-2026-07; TestU01 CPU dominates (~3.5–6 h wall)."
echo "See research/prng_quality/QUALITY_RESULTS.md."

cd "$ROOT"
# Do not use set -o pipefail on the pipeline alone: stats exits 0 on BrokenPipe
# when BigCrush finishes; docker may still exit 0. Prefer explicit statuses.
set +e
# stderr from stats → stats.log; binary stdout → docker stdin
# BigCrush text results from container stdout → tee
cargo run --release --bin stats -- --megabytes "$MEGABYTES" --output - 2>"${OUT}.stats.log" \
  | docker run --rm -i \
      --entrypoint bigcrush_stream \
      qs-crypto-testu01 \
  | tee "$OUT"
pipe_status=("${PIPESTATUS[@]}")
set -e

stats_rc="${pipe_status[0]:-0}"
docker_rc="${pipe_status[1]:-0}"
tee_rc="${pipe_status[2]:-0}"

if grep -q "=== BigCrush complete ===" "$OUT" 2>/dev/null; then
  echo "Done. Results: $OUT"
  exit 0
fi

if grep -q "bigcrush_stream: EOF/short read" "$OUT" "${OUT}.runlog" 2>/dev/null; then
  echo "ERROR: stream ended before BigCrush finished (raise BIGCRUSH_MEGABYTES or use 0)." >&2
  exit 2
fi

echo "ERROR: BigCrush did not complete (stats_rc=${stats_rc} docker_rc=${docker_rc} tee_rc=${tee_rc})." >&2
echo "See $OUT and ${OUT}.stats.log" >&2
exit 1
