# Publishing ReteGet on F-Droid

F-Droid does not take a finished APK. It clones this repository at a tagged commit, builds the app
on its own server with `scripts/build.sh --unsigned`, and compares the result with the signed APK on
the GitHub releases page. When the two match apart from the signature, F-Droid ships the signed
APK from GitHub (a reproducible build), so the F-Droid and GitHub downloads carry the same signature
and can update each other.

| Piece | Where |
|---|---|
| Unsigned build | `scripts/build.sh --unsigned` — the whole pipeline, stopping after `zipalign`; never reads a keystore. |
| Store metadata | `fastlane/metadata/android/{en-US,ko-KR}/` — title, descriptions, icon, feature graphic, screenshots, and a changelog per version **code**. |
| Build recipe | `docs/fdroid/com.reteget.yml` — the file that goes into `fdroiddata` as `metadata/com.reteget.yml`. |

## Rules that keep the build reproducible

- The release APK is built with **JDK 21**, the JDK on F-Droid's build server (Debian Trixie).
  `scripts/build.sh --release` refuses any other major version unless `RETEGET_JDK_MAJOR=any`.
- **build-tools 35.0.0**, with `apksigner --alignment-preserved`: without it apksigner re-aligns the
  archive while signing and the signature no longer fits a rebuild.
- The recipe does not pin `JAVA_HOME`; `scripts/env.sh` finds `javac` on `PATH`.
- Check a release before publishing it: build `--unsigned` from a fresh clone of the tag and run
  `apksigcopier compare reteget-<v>.apk --unsigned reteget-<v>-unsigned.apk`.

## Every release

1. Raise `android:versionCode` and `android:versionName` in `src/android/AndroidManifest.xml`.
2. Add `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` (and `ko-KR`).
3. Commit, tag `v<versionName>`, push the tag.
4. `scripts/build.sh --release` with JDK 21, and publish a GitHub release for the tag with the APK
   named `reteget-<versionName>.apk` — `Binaries:` points there and the F-Droid build fails without it.

`UpdateCheckMode: Tags` and `AutoUpdateMode: Version` make F-Droid pick up new tags by itself; no
merge request is needed for an ordinary release.

## The signing key

`AllowedAPKSigningKeys` names the release key. If the key is lost, no future version can update an
installed ReteGet, from F-Droid or from GitHub. Keep it backed up.
