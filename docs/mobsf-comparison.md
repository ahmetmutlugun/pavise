# Pavise vs MobSF Benchmark

Date: 2026-05-22. Apple Silicon. MobSF `opensecurity/mobile-security-framework-mobsf:latest` in Docker, pavise built `--release`. Pavise timed with hyperfine (3 warm runs); MobSF timed via REST API (3 sequential runs).

## Performance

| IPA | Size | Pavise (mean) | MobSF cold | MobSF warm | Speedup (cold) |
|---|---|---|---|---|---|
| DVIA-v2-swift | 19 MB | **0.261 s** | 8.09 s | 4.57–4.71 s | **31×** |
| Navic | 20 MB | **0.251 s** | 9.85 s | 4.82–4.95 s | **39×** |
| vlc-ios-2.8.5 | 81 MB | **0.875 s** | 17.77 s | 7.79–9.55 s | **20×** |

MobSF caches extracted IPAs to disk — subsequent runs of the same hash are ~2× faster than the first. Even against warm MobSF, pavise is 17–20× faster.

## Accuracy — DVIA-v2-swift (intentionally vulnerable, ground truth available)

| Real issue | Pavise | MobSF |
|---|---|---|
| ATS arbitrary loads | ✅ high | ✅ high |
| Stack canary absent (frameworks) | ✅ high | ❌ |
| ARC not detected | ✅ high | ❌ |
| Debug symbols not stripped | ✅ warn | ❌ |
| Insecure random | ✅ warn | ❌ |
| SSL/TLS cert validation bypass | ✅ high | ❌ |
| Weak crypto hash (MD5/SHA1) | ✅ warn | ❌ |
| `get-task-allow` entitlement | ✅ high | ❌ |
| Embedded `.der` cert file | ✅ high | ✅ hotspot |
| No certificate pinning | ✅ warn | ❌ |
| Dev provisioning profile | ✅ warn | ❌ |
| Expired provisioning profile | ✅ high | ❌ |
| `dlopen` runtime lib loading | ✅ warn | ❌ |
| Dangerous C funcs (strcpy, …) | ✅ warn | ✅ warn (lumped) |
| Tracker (Google Analytics) | ✅ 2 | ✅ 1 (+ categorization) |

MobSF's `code_analysis`, `macho_analysis`, and `binary_analysis` sections were **empty** for DVIA's main binary. It scored DVIA 25/100 from one ATS finding; pavise scored 60/100 (C) from 16 distinct issues.

### False-positive check

- MobSF reports **40 "hardcoded secrets" in VLC**. All are plist config keys (`network-caching`, `EnableVolumeGesture`, …) and Xcode `localizationKey` UUIDs. Zero are credentials. Pavise correctly returns 0.
- MobSF flags shared libraries as "PIE missing" — PIE is N/A for `.dylib`. Pavise correctly skips PIE on framework binaries and marks NX on ARM64 as "enforced by hardware (XN bit)" rather than as a finding.

### Where MobSF is more accurate than pavise

- **Email extraction.** DVIA has `prateek@damnvulnerableiosapp.com`, `test123@gmail.com` embedded; MobSF stringifies every Mach-O and finds them. Pavise returned 0 emails for DVIA, Navic, and VLC.
- **Tracker enrichment.** MobSF links trackers to Exodus-Privacy categories + URLs. Pavise emits name only.
- **Cert/key file enumeration.** MobSF lists every `.der`/`.pem` separately as a hotspot.

## Capability gaps (MobSF has, pavise doesn't)

| Capability | Status |
|---|---|
| Email extraction from binary strings | gap |
| Full strings dump | gap |
| VirusTotal integration (optional) | gap |
| App Store metadata lookup | gap |
| File-by-file IPA inventory in report | partial |
| Tracker categorization w/ external DB | partial |
| Suspicious-file heuristics | gap |
| Library inventory w/ versions | partial (`framework_components`) |
| Persistent scan DB / web UI | out of scope (different product) |

### Recommended pavise additions

1. ~~Email regex over the strings already extracted from Mach-Os.~~ **Done** — `src/patterns/emails.rs`.
2. ~~Bundle Exodus-Privacy tracker DB for category + reference URL per tracker.~~ **Done** — categories + website per tracker in `rules/trackers.yaml`.
3. ~~Structured `.der`/`.pem`/`.p12` file enumeration separate from the "embedded cert/key" finding.~~ **Done** — `src/resources/certs.rs` classifies by content: private keys/PKCS#12 → high `QS-CERT-001`, public certs → info `QS-CERT-002` (avoids flagging pinning anchors as key leaks).

## Methodology notes

- Pavise: `target/release/pavise <ipa> -o out.json -q`, hyperfine `--warmup 1 --runs 3`.
- MobSF: `POST /api/v1/upload` → `POST /api/v1/scan` via curl, wall-clock measured around both. `delete_scan` between runs (does not invalidate on-disk extraction cache, hence cold/warm split).
- Comparison limited to 3 IPAs; directional not statistical.
