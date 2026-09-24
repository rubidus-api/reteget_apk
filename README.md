# ReteGet

**ReteGet v0.3.3** (latest release) download — [apk (Android 2.3+)](https://github.com/rubidus-api/reteget_apk/releases/download/v0.3.3/reteget-0.3.3.apk) · [release notes](https://github.com/rubidus-api/reteget_apk/releases/tag/v0.3.3)

**English** · [한국어](README.ko.md)

**A lightweight, standalone file and APK downloader for legacy Android devices (Android 2.3+ Gingerbread through Android 4.x KitKat and newer).**

Download APKs, firmware images, and files directly on vintage devices without needing a PC, ADB, or modern app stores.

<p align="center">
  <img src="docs/screenshots/icon.png" alt="ReteGet app icon" width="96">
  &nbsp;&nbsp;&nbsp;
  <img src="docs/screenshots/icon-monochrome.png" alt="ReteGet monochrome icon as a themed Android 13 home screen paints it" width="96">
  <br>
  <sub>App icon: normal, and monochrome (themed icons, Android 13+)</sub>
</p>

<p align="center">
  <img src="docs/screenshots/screenshot_queue-0.3.1.png" alt="ReteGet download queue on Android 2.3: one download in progress, a failed one with Retry, and a finished one" width="220">
  &nbsp;&nbsp;
  <img src="docs/screenshots/screenshot_template-0.3.1.png" alt="ReteGet URL template with the version field and the resolved URL on Android 2.3" width="220">
  &nbsp;&nbsp;
  <img src="docs/screenshots/screenshot_presets-0.3.2.png" alt="ReteGet built-in rete presets with names, checksums and signers on Android 2.3" width="220">
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
- **Built-in TLS 1.3 / 1.2 Engine (works on Android 2.3)**: Android 2.3–4.x cannot talk to GitHub on their own: 2.3 has no TLS 1.2 at all, and 4.1 devices such as the Galaxy Note 2 fail with `SSLv3 alert handshake failure`. ReteGet carries its own TLS client written in plain Java: TLS 1.3 (RFC 8446) with X25519 or P-256 key exchange, AES-128-GCM, and ECDSA / RSA-PSS server signatures, falling back to TLS 1.2 (ECDHE + AES-GCM, Extended Master Secret) only for servers without TLS 1.3, with downgrade protection. X25519, AES-GCM, HKDF, ECDSA, RSA-PSS, X.509 parsing and certificate path validation are implemented in the app, because Android 2.3 cannot verify ECDSA certificates such as GitHub's. The server certificate chain and host name are always checked against the system and bundled root certificates. The engine is used automatically when the system TLS fails, or always with the checkbox. It is checked against the RFC 8448 handshake trace byte for byte and against independent TLS servers, and was verified by downloading from GitHub Releases on Android 2.3.7.
- **Download Queue at the Top**: Every download goes into a queue shown at the top of the screen, one file at a time so an old phone is not overloaded. Each entry shows its file name, state and URL, with the progress bar underneath while it downloads; a failed download says why and can be retried or deleted; a finished one can be installed (with the same checksum and signing-key warnings as right after the download) or its record deleted (the file stays). **Select all** and **Delete selected** under the title remove several entries at once. The list survives closing the app, and an entry interrupted that way comes back as failed so it can be retried.
- **Direct HTTP & Passive FTP**: Supports plain HTTP and zero-dependency RFC 959 passive mode FTP for fast local network or intranet software distribution.
- **Release URL Templates (`{1}`, `{2}`, `{version}`)**: Detects bracketed placeholder tokens in download URLs (such as `https://github.com/user/repo/releases/download/v{1}/app-{1}.apk`). When present, ReteGet dynamically generates small input boxes so you only need to type the version number to fetch an update.
- **Checksum & Hash Integrity Verification**: Verifies downloaded files against industry-standard hashes widely used by GitHub, GitLab, and open-source distributions: **SHA-256**, **SHA-1**, **MD5**, and **SHA-512**. You can paste raw hex digests, `sha256: <hash>`, or standard GNU `sha256sum` output lines (`<hash>  <filename>`). Automatically detects the algorithm, warns of corruption or tampering before installation, and provides one-tap hash copying.
- **APK Signature & Author Continuity Verification**: Automatically inspects the X.509 signing certificate of downloaded APKs and calculates its SHA-256 fingerprint. Verifies continuity against currently installed packages (preventing `INSTALL_FAILED_UPDATE_INCOMPATIBLE` signature conflicts) and previous download history (TOFU model). If author signing keys change or conflict, a clear warning dialog is displayed with an option to inspect details and override.
- **Rete Series Presets Built In**: ReteGet, ReteClock and ReteKey (the Android 4.0+ build, plus the Android 9+ build) come as ready-made version templates for GitHub Releases, with the expected SHA-256 and signing key already filled in. Your own presets are kept when the built-in list is updated.
- **Named Presets & History Management**: Give each preset a name (e.g. *ReteGet*, *ReteClock*) so template URLs are easy to tell apart. **Save** next to *Download* keeps the URL above as a preset. Each preset shows its name, URL and last download record in one wrapping paragraph, with short actions on top: **Use** (or tap the preset) loads it into the URL bar with the known version filled in, **Edit** (or press and hold) changes the name and URL, **Up**/**Dn** reorder, **Del** deletes; **Select all** and **Delete selected** work on the checked presets.
- **Settings Export and Import**: **Export** writes all settings (presets, options, and the signing keys seen for each app) to `reteget-settings-<date>.ini` in the Download folder and can copy the same text to the clipboard; **Import** reads such a file or the clipboard, shows what will change, and merges it: presets match by URL, presets only on this phone stay, and a signing key already recorded on this phone is never replaced. The file is plain text in the subset of INI and TOML that both read the same way (the rete family's settings format), so it can be read and edited by hand.
- **Paste and Clear**: next to *Target URL* and *Expected Checksum*, **Paste** takes the text from the clipboard and **Clear** empties the field.
- **Saves to the Download Folder**: Files go to the system Download folder (on Android 2.3 this is `/mnt/sdcard/Download`; "sdcard" is the name of the shared storage even on phones without a card slot). If shared storage is missing or busy (for example while mounted on a PC over USB), ReteGet saves into its own app storage instead, tells you so, and can still install APKs from there.
- **One-Touch APK Installation**: Once an `.apk` file finishes downloading, ReteGet immediately prompts to launch the system package installer (`Intent.ACTION_VIEW` with MIME type `application/vnd.android.package-archive`).
- **Unverified SSL Bypass Option**: Includes an optional checkbox to allow unverified or self-signed certificates when downloading from local test servers or home labs.
- **Ultra-Lightweight & Single-Dex**: About 173 KB APK size, single dex file, zero third-party libraries, and built without Gradle.

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
