#!/usr/bin/env bash
# Run dieharder + NIST STS on SpinPrng streams via Docker image qs-crypto-rng-tests
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA="${ROOT}/stats_out"
OUT="${ROOT}/benches/reports/v0.3/results"
mkdir -p "$OUT"

if ! docker image inspect qs-crypto-rng-tests >/dev/null 2>&1; then
  docker build -t qs-crypto-rng-tests "${ROOT}/scripts/rng_docker"
fi

echo "=== dieharder on all streams ==="
docker run --rm \
  -v "${DATA}:/data:ro" \
  -v "${OUT}:/out" \
  qs-crypto-rng-tests \
  bash -c '
    for f in /data/spinprng_qs256_stream*.bin; do
      [ -f "$f" ] || continue
      base=$(basename "$f" .bin)
      out="/out/${base}_dieharder.txt"
      if [ -s "$out" ] && grep -q "dab_monobit2\|PASSED" "$out" && [ "$(wc -l < "$out")" -gt 50 ]; then
        echo "skip dieharder $base (exists)"
        continue
      fi
      echo "=== dieharder $base ==="
      dieharder -a -g 201 -f "$f" | tee "$out"
    done
  '

echo "=== NIST STS (α=0.01, 1M bits × 100 streams) ==="
docker run --rm \
  -v "${DATA}:/data:ro" \
  -v "${OUT}:/out" \
  qs-crypto-rng-tests \
  bash -c '
    STS=/opt/sts-2.1.2/sts-2.1.2
    cd "$STS"
    (cd experiments && ./create-dir-script || true)
    for f in /data/spinprng_qs256_stream*.bin; do
      [ -f "$f" ] || continue
      base=$(basename "$f" .bin)
      out="/out/${base}_nist_finalAnalysisReport.txt"
      if [ -s "$out" ] && [ "$(wc -l < "$out")" -gt 20 ]; then
        echo "skip nist $base (exists)"
        continue
      fi
      echo "=== NIST $base ==="
      find experiments/AlgorithmTesting -type f -name "*.txt" -delete 2>/dev/null || true
      {
        echo 0
        echo "$f"
        echo 1
        echo 0
        echo 100
        echo 1
      } | ./assess 1000000 > "/out/${base}_nist.log" 2>&1 || true
      if [ -f experiments/AlgorithmTesting/finalAnalysisReport.txt ]; then
        cp experiments/AlgorithmTesting/finalAnalysisReport.txt "$out"
      fi
    done
  '

echo "=== Suite run complete ==="
ls -la "$OUT"
