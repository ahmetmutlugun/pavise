# Finding attribution and noise filtering

Fixes from an outside review (2026-09-25) that scanned six open-source sideload IPAs
(iSH, Aidoku, Feather, LiveContainer, Yattee, UTM Remote). Keep these rules when you add checks.

## Imported-API findings (`src/binary/symbols.rs`)

- `SymbolScanner::scan(imports, binary_path, Origin)` puts the binary in each evidence line
  (`ssl.1.1.framework: _EVP_des_cbc`).
- `Origin::Library` (embedded framework/dylib) lowers severity by one level (High → Warning,
  Warning → Info). Bundled OpenSSL importing DES used to raise a High finding and exit code 1.
- The main executable and app extensions are `Origin::App`, so their severity stays as it is.
- QS-API-023 (pinning API) only settles the pinning check when the main binary or an extension
  imports it. A framework import only shows that the library is able to pin.
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
- QS-ENT-003 (HealthKit) is Info unless `healthkit.access` has `health-records`.

## Distribution context

- QS-PROV-001 (development/ad-hoc profile) is unscored, like QS-BIN-005 and profile expiry.
  It describes how the build was distributed.
- The CLI summary prints a `Build:` line for unsigned and non-App-Store builds.
- QS-BIN-004 (unsigned) stays High.

## CLI

`--quiet` counts findings plus secrets, the same as the full summary (`severity_count`).
