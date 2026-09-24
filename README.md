# ReteGet

**English** · [한국어](README.ko.md)

**A lightweight, standalone file and APK downloader for legacy Android devices (Android 2.3+ Gingerbread through Android 4.x KitKat and newer).**

Download APKs, firmware images, and files directly on vintage devices without needing a PC, ADB, or modern app stores.

<p align="center">
  <img src="docs/screenshots/screenshot_template.png" alt="ReteGet URL template input on Android 4.4" width="240">
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/screenshots/screenshot_resolved.png" alt="ReteGet dynamic placeholder resolution" width="240">
</p>

---

## The Problem

Legacy Android smartphones and tablets (Android 2.3 through 4.4) remain capable hardware, but they are almost entirely cut off from the modern web:

1. **Obsolete TLS & Expired Certificates**: Modern web hosts (including GitHub) strictly mandate TLS 1.2+ with Server Name Indication (SNI). Android 2.3–4.0 lack native TLS 1.2, and Android 4.1–4.4 have TLS 1.2 disabled by default in stock socket factories. Furthermore, system root certificates (such as IdenTrust DST Root CA X3) expired in September 2021, causing SSL handshake failures on almost every modern site.
2. **Broken Stock Browsers**: Early WebViews and stock AOSP browsers crash or hang on modern JavaScript-heavy release pages.
3. **Dead App Stores**: Google Play Store and modern app stores no longer connect or support devices below Android 5.0+. Modern open-source stores require multi-megabyte Jetpack/AndroidX runtimes that cannot install on legacy systems.

## What ReteGet Does

ReteGet is a dedicated, framework-only Android utility that bridges the gap, allowing vintage hardware to fetch files and install APK updates directly over the air:

- **Modern TLS 1.2 & Bundled Root CAs**: Wraps SSL socket creation to force-enable TLS 1.2 on Android 4.x with SNI reflection support. Bundles modern Root CAs (ISRG Root X1, DigiCert Global Root CA/G2, USERTrust, Google Trust Services) so downloads from modern GitHub Releases and CDN hosts succeed without warnings.
- **Direct HTTP & Passive FTP**: Supports plain HTTP and zero-dependency RFC 959 passive mode FTP for fast local network or intranet software distribution.
- **Release URL Templates (`{1}`, `{2}`, `{version}`)**: Detects bracketed placeholder tokens in download URLs (such as `https://github.com/user/repo/releases/download/v{1}/app-{1}.apk`). When present, ReteGet dynamically generates small input boxes so you only need to type the version number to fetch an update.
- **Preset Management**: Save favorite download URLs and switch between them using an on-screen dropdown.
- **One-Touch APK Installation**: Once an `.apk` file finishes downloading to `/sdcard/Download`, ReteGet immediately prompts to launch the system package installer (`Intent.ACTION_VIEW` with MIME type `application/vnd.android.package-archive`).
- **Unverified SSL Bypass Option**: Includes an optional checkbox to allow unverified or self-signed certificates when downloading from local test servers or home labs.
- **Ultra-Lightweight & Single-Dex**: Under 70 KB APK size (~50 KB debug build), single dex file, zero third-party libraries, and built without Gradle.

## Target Platform & Compatibility

- **Minimum SDK**: Android 2.3 Gingerbread (API 9 / 10)
- **Primary Compatibility Floor**: Android 4.4 KitKat (API 19)
- **Target SDK**: Android 9.0 Pie (API 28)
- **Architecture**: Single-dex pure Java bytecode.

## Build and Installation

Built entirely with Android SDK command-line tools (`aapt2`, `javac`, `d8`, `zipalign`, `apksigner`):

```sh
scripts/build.sh              # dist/reteget-<version>-debug.apk, signed with a local dev key
scripts/build.sh --release    # dist/reteget-<version>.apk, requires RETEGET_KEYSTORE
scripts/build.sh --unsigned   # dist/reteget-<version>-unsigned.apk, for F-Droid to sign
scripts/test.sh               # run unit tests with standalone Java runner
```

The APK is signed with v1 (JAR signing) plus v2 and v3 schemes, so Android 2.3 through 4.4 accept the v1 signature and modern Android accepts v2/v3. Builds are fully reproducible (`TZ=UTC`, fixed zip epoch timestamps).

## The name

**rete** is Latin for *net*, and *-get* is just to fetch or retrieve over the wire (drawing heritage from classic Unix `wget` and HTTP `GET`).

The intended pronunciation is the Latin one: **RAY-teh-get** (three syllables, `rē-te-get`; the first vowel is the long *e* of *they*, the middle *e* is pronounced, never silent, and *-get* snaps shut).

If you would rather say it the way English usually treats this word, that is fine too. English borrowed *rete* as an anatomical term and pronounces it **REE-tee**, so **REE-tee-get** is a perfectly natural reading. Say it however you like; ReteGet will just quietly fetch the file.

## License

MIT. See `LICENSE`.
