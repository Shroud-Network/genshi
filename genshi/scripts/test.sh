#!/usr/bin/env bash
# Run all workspace tests and print a grand total at the end.
# Usage: ./scripts/test.sh [extra cargo-test args...]

set -euo pipefail

OUTPUT=$(cargo test --release "$@" 2>&1) || STATUS=$?
echo "$OUTPUT"

# Parse every "test result:" line and sum the columns.
PASSED=0 FAILED=0 IGNORED=0
while IFS= read -r line; do
    p=$(echo "$line" | sed -n 's/.*ok\. \([0-9]*\) passed.*/\1/p')
    f=$(echo "$line" | sed -n 's/.*; \([0-9]*\) failed.*/\1/p')
    i=$(echo "$line" | sed -n 's/.*; \([0-9]*\) ignored.*/\1/p')
    PASSED=$((PASSED + ${p:-0}))
    FAILED=$((FAILED + ${f:-0}))
    IGNORED=$((IGNORED + ${i:-0}))
done <<< "$(echo "$OUTPUT" | grep '^test result:')"

TOTAL=$((PASSED + FAILED + IGNORED))

echo ""
echo "========================================"
echo "  TOTAL: $TOTAL tests | $PASSED passed | $FAILED failed | $IGNORED ignored"
echo "========================================"

exit ${STATUS:-0}
