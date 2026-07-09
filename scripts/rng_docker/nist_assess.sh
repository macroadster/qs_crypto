#!/bin/bash
# Non-interactive NIST SP 800-22 assess wrapper
# Usage: nist_assess <file> [bits_per_stream] [num_streams]
set -euo pipefail
FILE="${1:?usage: nist_assess <file> [bits_per_stream] [num_streams]}"
BITS="${2:-1000000}"
NUM="${3:-100}"
STS_ROOT="/opt/sts-2.1.2/sts-2.1.2"
cd "$STS_ROOT"
# Menu sequence for STS 2.1.2 assess:
#   0          = Input File generator
#   FILE       = path
#   1          = apply ALL statistical tests (0 = select subset)
#   0          = continue past parameter adjustments
#   NUM        = number of bit streams
#   1          = binary input mode (0 = ASCII)
printf '0\n%s\n1\n0\n%s\n1\n' "$FILE" "$NUM" | ./assess "$BITS"
echo "=== NIST STS finished for $FILE (bits=$BITS streams=$NUM) ==="
REPORT=$(find experiments -name 'finalAnalysisReport.txt' -type f 2>/dev/null | head -1)
if [ -n "$REPORT" ]; then
  echo "=== finalAnalysisReport.txt ==="
  cat "$REPORT"
fi
