# App Store privacy checks

App Store Connect rejects builds for privacy-manifest problems. Pavise detects these
statically so a build can be checked before upload. The code is in `src/manifest/privacy.rs`.

| Rule | Apple error | What pavise checks |
|---|---|---|
| QS-PRIV-001 | — | The main bundle has no `PrivacyInfo.xcprivacy` (Info) |
| QS-PRIV-002 | ITMS-91053 | The main binary imports a required-reason API whose category the app manifest doesn't declare (Info) |
| QS-PRIV-003 | ITMS-91061 | A framework on Apple's SDK list has no `PrivacyInfo.xcprivacy` inside it (Warning) |

## QS-PRIV-003 (listed SDKs)

- The list is `data/privacy_sdks.txt`, from
  <https://developer.apple.com/support/third-party-SDK-requirements/>. It is refreshed by hand
  (not by the EOL job). `BoringSSL / openssl_grpc` is split into two names.
- A framework matches when its `.framework` directory name equals a listed name, ignoring case.
  `AlamofireImage` doesn't match `Alamofire`. Frameworks inside extensions and Watch apps count.
- The manifest may be anywhere inside the framework directory, including a nested resource
  bundle (`SDWebImage.framework/SDWebImage.bundle/PrivacyInfo.xcprivacy`).
- Apple enforces this for new apps and for updates that *add* a listed SDK. An app that already
  shipped with the SDK may be grandfathered, so the rule is a Warning, not High.
- Corpus check (2026-10-26): 9 hits in 7 of 33 apps. All hits are SDK versions from before
  manifests existed (Alamofire 4.5.1, RealmSwift 2.10.2, MBProgressHUD 1.2.0, Hermes in
  Mattermost). No false positives on the 20+ listed frameworks that ship a manifest.

## Not covered yet

- **Statically linked listed SDKs.** Swift packages and static CocoaPods ship their manifest
  as a resource bundle (`Firebase_FirebaseCore.bundle`, `<Pod>_Privacy.bundle`). When that
  bundle is missing, the SDK can only be detected from symbols (ObjC classes, Swift module
  names), which is still to do.
- **Required-reason APIs in frameworks and extensions (tried and shelved 2026-10-26).**
  Comparing each framework's or extension's imports with its own manifest plus the app's
  flagged 228 uses in 18 of 33 apps. Apple's real check is narrower than that. Bitwarden
  v2026.4.1 is on the App Store with regular updates, yet its
  `BitwardenSdk…PackageProduct.framework` imports `stat`/`statfs` and none of its 14
  manifests declares FileTimestamp or DiskSpace. Until we know what Apple matches (which
  symbols, which binaries, which manifests count), a finding here would claim rejections that
  don't happen. Ground truth would be an App Store Connect upload of a test app; see
  `../pavise-testapps`.
- **SDK signatures.** Xcode checks these at build time. They aren't visible in an IPA.
