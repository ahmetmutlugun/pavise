# Backend Remediation Plan

Source: backend review + 33-IPA corpus scan, 2026-09-24. Supersedes the deleted
`PLAN.md` / `TEST_COVERAGE_PLAN.md` (March 2026); still-valid items merged below.
Verify each item against current code before starting — line refs drift.

## P0 — Wrong results / fail-open

- [x] **Rules not shipped outside Docker.** `release.yml` tarballs, `install.sh`, the GitHub Action and
  `cargo install` ship only the binary; every loader treats a missing rules file as "no rules"
  (`engine.rs`, `symbols.rs`, `trackers.rs`, `info_plist.rs:80`). Telegram: 38/F with rules, 58/D without.
  Fix: embed defaults with `include_str!`, let `--rules` override; exit 2 if an explicit dir is incomplete.
- [x] **Score computed before network findings** (`lib.rs` step 4 vs step 5) → CVE/OFAC deductions are dead. Score last.
- [x] **Main-binary parse failure inflates the score** (only `debug!`). Surface an error finding / exit 2.
- [x] **QS-BIN-008 ID collision**: "framework without canary" and "DWARF path leak" (`macho.rs`). Split into two IDs.
- [x] **OSV lookup always 400s**: `CocoaPods`/`SwiftPM` are invalid ecosystems (`osv.rs:129-150`). Use `SwiftURL`
  + repo URL from `Package.resolved` (`location`/`repositoryURL`); log failures at `warn!`.

## P1 — Scoring redesign (`scoring/owasp.rs`)

Was: dev build with `get-task-allow` = 92/A; Bitwarden = 66/C. Now (2026-09-24): 66/C, 83/B.
Model: `scoring/owasp.rs` — severity × `ScoreClass` weight, one deduction per root cause, per-class caps.
- [x] Deduct by **severity × category**, not a hand-picked ID list. Today ENT, PROV, CERT-001 (private key),
  CRYPTO, SANDBOX, NET-002/004, STORE never affect the score.
- [x] Info findings (`_malloc`, `_NSLog`, permissions, QS-API-023 "pinning detected") must not deduct.
- [x] One deduction per root cause: framework canary is counted via protections **and** QS-BIN-008;
  QS-SEC-001 and QS-SEC-025 are the same regex (drop 025).
- [x] Never score FairPlay encryption (Apple-applied; `is_dev_build` heuristic misfires on unsigned CI builds).
- [x] Stable rule IDs: `QS-PERM-<key>` / `QS-IPC-001-<scheme>` → fixed IDs + key in evidence (SARIF/baseline).
- [x] Add corpus golden test: `tests/corpus_grades.rs` (`cargo test --release --test corpus_grades -- --ignored`).

## P1 — Dead rules and false positives

- [x] `ios_apis.yaml`: ObjC classes import as `_OBJC_CLASS_$_X` → UIWebView/NSUserDefaults/WKWebView/CoreData/
  Realm/TrustKit rules never match. `_kCCAlgorithmDES`, `_kCCOptionECBMode` are enums, `_writeToFile` a selector.
- [x] QS-API-016 HIGH on `_CCCryptorCreateWithMode` (used by AES-CTR/GCM) — remove from DES rule.
- [x] QS-API-023 / pinning: `_SecCertificateCreateWithData` and any bundled public cert count as "pinning" → NET-004 suppressed. Tighten.
- [x] ARC check keys on `_objc_release/_retain` (also emitted under MRC); use `_objc_storeStrong`/`_objc_retainAutoreleasedReturnValue`.
- [x] Secrets: add `\b` + reject Rust hash suffix `17h[0-9a-f]{16}E` (Monal `hf_…` FP); skip `Symbols/*.symbols`
  (Skia `ghp_…` FP); QS-SEC-006 fires on minified JS/Dart; QS-SEC-024 must decode JWT and require `service_role`;
  QS-SEC-023 misses `sk-proj-`; QS-SEC-010 add `gh[ousr]_`, `github_pat_`; QS-SEC-027 require `user:pass@`;
  QS-SEC-008 `pk_live` → info; QS-SEC-015 Mapbox regex effectively dead; QS-SEC-028 matches Swift source only.
- [x] Quoted `key = "value"` rules (SEC-003/005/006/016/017/019/020/026) can't match Mach-O or XML plists:
  allow optional quotes and add a parsed-plist key/value pass (binary plists are scanned as raw bytes today).
- [x] Entropy thresholds unreachable for 20–32 char tokens; hex secrets dropped (`entropy.rs:138,184`). Normalise by charset.
- [x] Private key reported twice (QS-CERT-001 + QS-SEC-004). `.key` Keynote files → HIGH; add `.p8`, `.jks`, `.keystore`.
- [x] QS-NET-001 fires on license/namespace URLs (apache.org in acknowledgements). QS-NET-003 flags version
  strings (`1.0.4.0`, `1.00.02.28`) — reject leading zeros, require context. URL noise filter uses `contains` → match parsed host.
- [x] `NSAllowsArbitraryLoads` is HIGH even when `…InWebContent` makes iOS ignore it (`info_plist.rs:214`).
- [x] QS-PROV-002 (expired profile) HIGH on 15/33 apps and date-dependent exit code → Info.
- [x] Entitlements check macOS keys (`com.apple.security.cs.*`); iOS uses `dynamic-codesigning`.
- [x] Secret matches drop CWE/OWASP/remediation (`SecretMatch` lacks fields) → absent from OWASP summary.
- [x] OWASP mapping mixes 2016/2024 (secrets→M9 should be M1; storage→M2 should be M9); MASVS uses v1 `MSTG-*`.
  One table keyed by rule ID.

## Found during P0/P1 (2026-09-24)

- [x] ZIP names without the UTF-8 flag were CP437-decoded → Hebrew bundle (hamagen) scanned with no binary.
- [x] Scan errors exited 1 (same as "high findings"); now 2. `uuid_re` matched any 36 hex chars.
- [x] QS-BIN-002 (no canary) fired on stub/Swift-only mains (Telegram, Binary-Clock, mhabit). Now Info when
  `__text` < 64 KiB or Swift with no libc buffer imports (`canary_not_applicable`); FunkiniOS stays High.
- [x] Entropy: Lottie JSON skipped by content (`is_lottie_json`); regex rules still run on it.

## P1 — Server hardening (`serve.rs`, internet-facing)

- [x] Zip bomb: entries read via `take(declared+1)`; overrun fails the scan.
- [x] Memory: IPA hashed/unzipped by streaming (Provenance RSS 4.3→3.1 GB); server cap `PAVISE_MAX_EXTRACTED_BYTES`.
- [x] PDF endpoint: rate limit + `PAVISE_MAX_PDF` permit held until Chrome exits; per-call deadline.
- [x] Body timeout layer; permit taken after upload + cache check, owned by the blocking task. Header timeout: proxy.
- [x] Uploads are `TempPath`s (no leak on panic); busy keeps session for retry; sessions capped (16, 2/IP).
- [x] `&e[..90]` UTF-8 panic → `truncate_chars`.
- [x] Store/cache capped (`insert_capped`, shared `Arc`); proxy headers only from `PAVISE_TRUSTED_PROXY` peers.
- [x] Handlers moved to `src/server/handlers.rs`; `serve.rs` is startup only. See [server.md](server.md).

## P2 — Coverage gaps (done 2026-09-24)

- [x] `.appex` extensions (`PlugIns/`, `Extensions/`): binary + entitlements, `extension_binaries` in the
  report; provisioning is `<bundle>/embedded.mobileprovision`, not the first `ends_with` match.
- [x] Info.plist: QS-PLIST-001 (`MinimumOSVersion` < 15), QS-PLIST-002 (sensitive `UIBackgroundModes`);
  `manifest/privacy.rs`: QS-PRIV-001 (no `PrivacyInfo.xcprivacy`), QS-PRIV-002 (required-reason API
  imported but undeclared); QS-ENT-012 data protection (None → Warning, absent/CUFUA → Info); iOS 17
  calendar/reminder keys. All Info except ENT-012 None, so grades are unchanged.
- [x] QS-API-024 `kSecAttrAccessibleAlways*` (Info: wrappers reference every class), QS-API-008 also on
  `UIPasteboard` class refs, QS-API-025 keyboard-extension blocking. Keyboard *cache* (per-field
  `autocorrectionType`) is runtime state — not statically decidable. `__ustring` UTF-16 literals scanned.
- [x] Firebase: `STORAGE_BUCKET` parsed; `--network` probes RTDB `/.json?shallow=true` and Storage object
  list (QS-FB-001/002, High on HTTP 200); only Google hosts / validated bucket names are requested.
- [x] Static SDKs: `trackers.yaml` `objc_classes` matched against `__objc_classname` of the main binary →
  trackers + SCA components `(statically linked)`. Firebase `Google` prefix dropped.
- [x] APK stubs removed (`.apk` → exit 2, iOS-only CLI/Cargo text); `sync_vulns.sh` deleted (OSV is live).

## Carried over from TEST_COVERAGE_PLAN (done 2026-09-24)

- [x] `fuzz/`: cargo-fuzz targets `zip_unpack`, `macho_analyze`, `plist_analyze`, `pattern_scan`,
  `entropy_scan`; nightly `.github/workflows/fuzz.yml` (5 min each). Not run locally (no nightly toolchain).
- [x] Golden file: `tests/golden_report.rs` vs `tests/golden/fixture_report.json` (`PAVISE_UPDATE_GOLDEN=1`).
- [x] Server tests: non-IPA, oversize chunk + direct body (found 200-instead-of-413 bug), concurrency,
  unknown ID, TTL expiry (`evict_expired`, TTL also checked on read), PDF download (needs Chrome).
- Dropped: ip-api.com failure tests (GeoIP is offline now); PLAN.md distribution items (not backend).
