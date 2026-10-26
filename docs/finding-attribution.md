# Finding attribution and noise filtering

Fixes from outside reviews: six open-source sideload IPAs (2026-09-25), and an unstripped
development build of a Firebase app (2026-10-05). Keep these rules when you add checks.

## Imported-API findings (`src/binary/symbols.rs`)

- `SymbolScanner::scan(imports, binary_path, Origin)` puts the binary in each evidence line
  (`ssl.1.1.framework: _EVP_des_cbc`).
- `Origin::Library` (embedded framework/dylib) lowers severity by one level (High → Warning,
  Warning → Info). Bundled OpenSSL importing DES used to raise a High finding and exit code 1.
- The main executable and app extensions are `Origin::App`, so their severity stays as it is.
- QS-API-023 (pinning API) only settles the pinning check when the main binary or an extension
  imports it. A framework import only shows that the library is able to pin.
- Call sites (`src/binary/callsites.rs`, unstripped arm64 only): `attribute_callers` maps
  every `BL`/`B` into an import's `__stubs` entry to the function containing it. The function's
  debug-map object file (N_OSO + N_FUN) gives the module: `x.build/` → `x`,
  `libPods-App-gRPC-Core.a(…)` → `gRPC-Core`. Evidence becomes `App: _strcpy — called from
  gRPC-Core ×12, App (app code) ×1`. The app module is the one defining `_main`. When every call
  site is in another module, severity drops one level, as for `Origin::Library`. Without a debug
  map or a call site (function pointers), the finding stays as it is. Caveat: an app whose own
  code is a static library (Haxe `libApplicationMain.a`) would read as a dependency.
- Aggregated framework findings describe the rule by its title. Earlier code cut the first
  description at `'`, which broke on "app's".

## RPATH (`is_safe_rpath` in `src/binary/macho.rs`)

`@executable_path` / `@loader_path` paths with at most two `..` stay inside the signed `.app`.
Xcode gives extensions `@executable_path/../../Frameworks`, so that path is safe too.

## URLs and domains (`src/patterns/urls.rs`, `scan_strings` in `src/lib.rs`)

- Noise URLs are neither flagged (QS-NET-001) nor collected as domains. Noise means schemas
  (`.xsd/.dtd/.xslt`, `…#`, `/ns`, `/xmlns`), license/COPYING files, `bugzilla.`/`bugs.` hosts,
  PKI URLs, invalid hosts (`x.x.x.x`, `%.*s`), and the hosts in `NOISE_HOSTS`.
- `trim_url` strips trailing prose punctuation (`https://x.app).` → `https://x.app`).
- `is_reference_file` skips URL extraction in license/credits/readme files and media/ROM
  files. Secrets in those files are still scanned.
- `is_endpoint_source` means Mach-O binaries, config files, `.jsbundle`, and `www/` or `public/`
  web-app JS. Only these count toward QS-NET-004. An HTTP URL in any other bundled JS/HTML is
  reported as Info.

- Binary plists (including compiled `.strings`) are URL-scanned from their parsed values
  (`plist_strings`). Raw byte runs glue a URL to the next object (`x.firebaseio.com[6453…`).
- A trailing `#` marks a namespace only when there is a path before it (`send.bitwarden.com/#`
  is a page). `[`/`]` end the host in `is_noise_url` too.
- Config-declared hosts join `domains` without a scheme: ATS `NSExceptionDomains` keys and the
  Firebase `DATABASE_URL` host. MobSF finds more domains (33 vs 13 in one review), but on the
  corpus at least 85% of its extras are PKI, schema, license or garbage hosts.
- Emails need a TLD from IANA's root zone (`data/tlds.txt`) and valid DNS labels. Protobuf
  names (`2@.envoy.config.cluster.v3…`) were reported as emails.
- `rules/trackers.yaml` lists tracking SDKs only. gRPC was removed: it is a library, and SCA
  lists it. SDKs found only by ObjC class appear under `trackers`, not as versionless components.

## SCA (`src/resources/sca.rs`)

- Framework plist versions `1.0`, `1`, `0.0.0` and `$(…)` are template placeholders. They are
  reported as unknown.
- Versions from library banners and end-of-life lines (QS-SCA-001): see
  [eol-data.md](eol-data.md).

## Binary hardening (`src/binary/macho.rs`)

- Apple's `ld` never embeds DWARF. An unstripped build keeps the debug map as stabs instead
  (N_SO/N_OSO/N_FUN…). Any stab other than N_OPT `radr://5614542`, which `strip` always leaves,
  means QS-BIN-007. Local symbols alone (Feather, Delta) are not flagged.
- QS-BIN-010 uses N_SO/N_OSO build paths from the main executable only.
- The 64 KB launcher-stub canary exemption applies to main executables only. A small C
  framework without a canary is QS-BIN-008.
- Any `#available` check that back-deploys links compiler-rt's `__isOSVersionAtLeast`. It
  parses `SystemVersion.plist` with `sscanf`. When `__cstring` holds that path and
  `CFPropertyListCreateWithData`, `api_imports()` drops `_sscanf` before the API rules run.
  8 of 33 corpus apps had API-001 from this import alone.
- QS-ENT-003 (HealthKit) is Info unless `healthkit.access` has `health-records`.

## Distribution context

- QS-PROV-001 (development/ad-hoc profile) is unscored, like QS-BIN-005 and profile expiry.
  It describes how the build was distributed.
- With a development profile, QS-ENT-001 (get-task-allow) drops to Info. Xcode always grants it
  there. Ad-hoc, enterprise and App Store builds keep it High.
- QS-SEC-004 keys listed in `data/known_test_keys.txt` (mbedTLS's four unencrypted test keys,
  found in Provenance's RetroArch and the Haxe FunkiniOS build) are Info as "Library Test Private Key".
- QS-SEC-001 (Google/Firebase API key) is Info. The keys are public by design. The risk is
  key restrictions and backend rules. `--network` probes RTDB/Storage (QS-FB-001/002). A
  refused probe is reported as Secure evidence.
- The CLI summary prints a `Build:` line for unsigned and non-App-Store builds.
- QS-BIN-004 (unsigned) stays High.

## CLI

`--quiet` counts findings plus secrets, the same as the full summary (`severity_count`).
