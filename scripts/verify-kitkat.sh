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
"$ADB" install -r "$APK" < /dev/null

echo "==> launching ReteGet activity"
"$ADB" shell am start -n com.reteget/org.reteget.apk.MainActivity < /dev/null >/dev/null
sleep 20

echo "==> capturing initial screen with template placeholder"
"$ADB" shell screencap -p /data/local/tmp/reteget_screen1.png < /dev/null
"$ADB" pull /data/local/tmp/reteget_screen1.png "$SHOTS/screenshot_template.png" < /dev/null
echo "    saved docs/screenshots/screenshot_template.png"

echo "==> entering version number in template field"
"$ADB" shell input keyevent KEYCODE_TAB < /dev/null
"$ADB" shell input text "1.20.0" < /dev/null
sleep 3

echo "==> capturing screen with resolved URL preview"
"$ADB" shell screencap -p /data/local/tmp/reteget_screen2.png < /dev/null
"$ADB" pull /data/local/tmp/reteget_screen2.png "$SHOTS/screenshot_resolved.png" < /dev/null
echo "    saved docs/screenshots/screenshot_resolved.png"

echo "==> scrolling down to presets section"
"$ADB" shell input swipe 160 550 160 150 300 < /dev/null
sleep 2

echo "==> capturing bottom presets list"
"$ADB" shell screencap -p /data/local/tmp/reteget_screen3.png < /dev/null
"$ADB" pull /data/local/tmp/reteget_screen3.png "$SHOTS/screenshot_presets.png" < /dev/null
echo "    saved docs/screenshots/screenshot_presets.png"

echo "==> verify app process is running cleanly"
"$ADB" shell ps < /dev/null | grep -q "com.reteget" || fail "ReteGet crashed on launch"
echo "    ReteGet process is alive: PASS"

echo "==> verify-kitkat complete"
