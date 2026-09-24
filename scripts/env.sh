#!/bin/sh
# Toolchain locations for reteget_apk build and test scripts.
set -e

if [ -n "${RETEGET_ROOT:-}" ]; then
    ROOT=$(cd "$RETEGET_ROOT" && pwd)
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

# Use the workspace shared JDK/Android SDK if available
if [ -f "$ROOT/../usr/gradle-env.sh" ]; then
    AI_SHARE_USR="$ROOT/../usr"
    export AI_SHARE_USR
    . "$AI_SHARE_USR/gradle-env.sh"
fi

if [ -f "$ROOT/scripts/env.local.sh" ]; then
    . "$ROOT/scripts/env.local.sh"
fi

: "${ANDROID_SDK_ROOT:=${ANDROID_HOME:-}}"
: "${ANDROID_BUILD_TOOLS_VERSION:=35.0.0}"
: "${ANDROID_COMPILE_API:=19}"
: "${ANDROID_RES_API:=34}"

fail() {
    echo "reteget_apk: $1" >&2
    exit 1
}

require_jdk() {
    if [ -z "${JAVA_HOME:-}" ]; then
        javac_path=$(command -v javac 2>/dev/null) \
            || fail "no JDK: set JAVA_HOME, or put javac on PATH"
        javac_real=$(readlink -f "$javac_path" 2>/dev/null || printf '%s' "$javac_path")
        JAVA_HOME=$(dirname "$(dirname "$javac_real")")
    fi

    JAVAC="$JAVA_HOME/bin/javac"
    JAVA="$JAVA_HOME/bin/java"
    JAR="$JAVA_HOME/bin/jar"
    KEYTOOL="$JAVA_HOME/bin/keytool"
    [ -x "$JAVAC" ] || fail "no javac in JAVA_HOME ($JAVA_HOME)"
    PATH="$JAVA_HOME/bin:$PATH"
    export PATH JAVA_HOME JAR
}

require_sdk() {
    [ -n "$ANDROID_SDK_ROOT" ] || fail "ANDROID_SDK_ROOT is not set"
    BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/$ANDROID_BUILD_TOOLS_VERSION"
    ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-$ANDROID_COMPILE_API/android.jar"
    ANDROID_RES_JAR="$ANDROID_SDK_ROOT/platforms/android-$ANDROID_RES_API/android.jar"
    AAPT2="$BUILD_TOOLS/aapt2"
    D8="$BUILD_TOOLS/d8"
    ZIPALIGN="$BUILD_TOOLS/zipalign"
    APKSIGNER="$BUILD_TOOLS/apksigner"
    [ -d "$BUILD_TOOLS" ] || fail "missing build-tools $ANDROID_BUILD_TOOLS_VERSION"
    [ -f "$ANDROID_JAR" ] || fail "missing platform android-$ANDROID_COMPILE_API"
    [ -f "$ANDROID_RES_JAR" ] || fail "missing platform android-$ANDROID_RES_API"
}
