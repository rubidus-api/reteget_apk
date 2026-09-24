#!/bin/sh
# Runs core Java unit tests for reteget_apk.
set -e

TZ=UTC
export TZ

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/scripts/env.sh"

require_jdk

OUT="$ROOT/build/test"
CLASSES="$OUT/classes"

rm -rf "$CLASSES"
mkdir -p "$CLASSES"

echo "==> compiling core unit tests"
find "$ROOT/src/core/java" "$ROOT/tests/core/java" -name '*.java' > "$OUT/test_sources.txt"

"$JAVAC" \
    -source 8 -target 8 \
    -encoding UTF-8 \
    -d "$CLASSES" \
    @"$OUT/test_sources.txt"

echo "==> executing TestRunner"
(cd "$ROOT" && "$JAVA" -cp "$CLASSES" org.reteget.core.TestRunner)
