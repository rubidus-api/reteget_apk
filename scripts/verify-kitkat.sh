#!/bin/sh
# End-to-end check on a real Android 4.4 (API 19) system image.
# Boots headless emulator, installs APK, tests UI, and captures screenshots.

set -e

ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/scripts/env.sh"
. "$ROOT/scripts/emulator.sh"

require_jdk
require_sdk

AVD="${RETEGET_AVD:-kitkat_x86}"
APK=$(emulator_apk "${1:-}")
[ -n "$APK" ] && [ -f "$APK" ] || fail "no APK found; run scripts/build.sh first"

OUT="$ROOT/build/verify"
SHOTS="$ROOT/docs/screenshots"
rm -rf "$OUT"
mkdir -p "$OUT" "$SHOTS"

trap emulator_cleanup EXIT

emulator_boot "$AVD" "$OUT/emulator.log" "-gpu swiftshader_indirect"

echo "==> installing $(basename "$APK")"
"$ADB" logcat -c || true
"$ADB" install -r "$APK"

echo "==> launching ReteGet activity"
"$ADB" shell am start -n org.reteget.apk/.MainActivity
sleep 8

echo "==> capturing initial screen with template placeholder"
"$ADB" shell screencap -p /data/local/tmp/reteget_screen1.png
"$ADB" pull /data/local/tmp/reteget_screen1.png "$SHOTS/screenshot_template.png"
echo "    saved docs/screenshots/screenshot_template.png"

echo "==> entering version number in template field"
# Tap on the dynamic EditText for {1} (around middle screen) or send tab/text
"$ADB" shell input keyevent KEYCODE_TAB
"$ADB" shell input text "1.20.0"
sleep 2

echo "==> capturing screen with resolved URL preview"
"$ADB" shell screencap -p /data/local/tmp/reteget_screen2.png
"$ADB" pull /data/local/tmp/reteget_screen2.png "$SHOTS/screenshot_resolved.png"
echo "    saved docs/screenshots/screenshot_resolved.png"

echo "==> verify app process is running cleanly"
"$ADB" shell ps | grep -q "org.reteget.apk" || fail "ReteGet crashed on launch"
echo "    ReteGet process is alive: PASS"

echo "==> verify-kitkat complete"
