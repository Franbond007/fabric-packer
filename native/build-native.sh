#!/usr/bin/env bash
# Builds the native crypto core for Linux (packcore.so) or macOS (packcore.dylib).
# Requires: clang (or gcc via CC=gcc) and a JDK (for jni.h). Set JAVA_HOME.
#   JAVA_HOME=/path/to/jdk ./build-native.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${JAVA_HOME:-}" ]; then
  # Best-effort discovery via java.home.
  JAVA_HOME="$(java -XshowSettings:properties -version 2>&1 | sed -n 's/.*java.home = //p' | head -n1)"
fi
if [ ! -f "$JAVA_HOME/include/jni.h" ]; then
  echo "JDK headers not found (set JAVA_HOME): $JAVA_HOME" >&2
  exit 1
fi

cc="${CC:-clang}"
src="$here/packcore.c"
os="$(uname -s)"
common=(-O2 -Wall -Wextra -std=c11 -fvisibility=hidden -fPIC -pthread
        -I"$JAVA_HOME/include")

case "$os" in
  Linux)
    out="$here/packcore.so"
    "$cc" "${common[@]}" -I"$JAVA_HOME/include/linux" -shared -s -o "$out" "$src"
    ;;
  Darwin)
    out="$here/packcore.dylib"
    "$cc" "${common[@]}" -I"$JAVA_HOME/include/darwin" -shared -o "$out" "$src"
    strip -x "$out"
    ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

echo "Native core built: $out ($(wc -c < "$out") bytes)"
