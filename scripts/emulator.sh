#!/bin/sh
# Shared emulator startup and management routines for reteget_apk.
# Sourced by verification and screenshot scripts.

set -e

emulator_boot() {
    _avd=$1
    _log=$2
    _extra=${3:-}

    ADB="$ANDROID_SDK_ROOT/platform-tools/adb"
    EMULATOR="$ANDROID_SDK_ROOT/emulator/emulator"
    [ -x "$EMULATOR" ] || fail "emulator package is not installed"

    ANDROID_HOME="$ANDROID_SDK_ROOT"
    : "${ANDROID_AVD_HOME:=$HOME/.android/avd}"
    export ANDROID_HOME ANDROID_SDK_ROOT ANDROID_AVD_HOME

    rm -f "${ANDROID_AVD_HOME:-$HOME/.android/avd}/$_avd.avd/hardware-qemu.ini.lock" 2>/dev/null || true

    _accel=""
    [ -w /dev/kvm ] || _accel="-accel off"

    echo "==> booting $_avd (this takes a few minutes without KVM)"
    # shellcheck disable=SC2086
    "$EMULATOR" -avd "$_avd" -no-window -no-audio -no-snapshot -no-boot-anim \
        -partition-size 2048 -wipe-data $_accel $_extra >"$_log" 2>&1 &

    i=0
    while [ -z "${ANDROID_SERIAL:-}" ]; do
        for serial in $("$ADB" devices | awk '/^emulator-/{print $1}'); do
            if [ "$("$ADB" -s "$serial" emu avd name 2>/dev/null | head -1 | tr -d '\r')" = "$_avd" ]; then
                ANDROID_SERIAL="$serial"
                export ANDROID_SERIAL
                break
            fi
        done
        [ -n "${ANDROID_SERIAL:-}" ] && break
        i=$((i + 1))
        [ "$i" -gt 60 ] && fail "the emulator for $_avd never appeared in adb devices"
        sleep 5
    done
    echo "    device: $ANDROID_SERIAL"

    "$ADB" wait-for-device
    i=0
    while [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n')" != "1" ]; do
        i=$((i + 1))
        [ "$i" -gt 120 ] && fail "emulator did not finish booting"
        sleep 10
    done
    echo "    booted: Android $("$ADB" shell getprop ro.build.version.release | tr -d '\r\n')" \
         "(API $("$ADB" shell getprop ro.build.version.sdk | tr -d '\r\n'))"

    echo "==> waiting for the package manager"
    i=0
    until "$ADB" shell pm list packages 2>/dev/null | grep -q "package:android"; do
        i=$((i + 1))
        [ "$i" -gt 40 ] && fail "package manager never came up"
        sleep 10
    done
}

emulator_cleanup() {
    if [ -n "${ANDROID_SERIAL:-}" ]; then
        echo "==> shutting down emulator $ANDROID_SERIAL"
        "$ADB" -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 || true
    fi
}

emulator_apk() {
    if [ -n "${1:-}" ]; then
        echo "$1"
        return
    fi
    ls -t "$ROOT"/dist/*.apk 2>/dev/null | grep -v -- '-unsigned\.apk$' | head -1
}
