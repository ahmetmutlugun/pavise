# Pavise Development Guide

## Overview
Pavise is a fast iOS IPA static security analyzer (target: <3s scan time). Phase 1 MVP complete; Phase 2 (Android APK, ELF) and Phase 3 (expanded reporting) are stubs.

## Project Structure
- **src/main.rs**: CLI (clap) with IPA/APK dispatch
- **src/lib.rs**: Orchestrator (`scan_ipa()` entry point)
- **src/unpacker/**: ZIP extraction (IPA), binary location, hashing
- **src/manifest/**: Info.plist, entitlements, provisioning profile parsing
- **src/binary/**: Mach-O/ELF parsing (goblin 0.8), symbol extraction
- **src/patterns/**: Regex-based scanning (secrets, trackers, URLs, emails)
- **src/resources/**: Firebase config, ATS/network security, SCA (framework analysis)
- **src/scoring/**: OWASP-based 0-100 scoring with A-F grading
- **src/report/**: JSON, SARIF 2.1.0, HTML Tera template output
- **src/network/**: DNS/geolocation via ip-api.com (optional --network flag)
- **src/types.rs**: Serializable domain model (ScanReport, Finding, SecretMatch, etc.)
- **rules/**: YAML rule files (secrets.yaml, ios_apis.yaml, permissions.yaml, trackers.yaml)

## Key goblin 0.8 Quirks
- Fat binaries: `Mach::Fat(fat)` → `fat.get(i)?` returns `SingleArch`, not direct `MachO`
- `macho.data` is private — pass raw `&[u8]` separately for string extraction
- Encryption: `CommandVariant::EncryptionInfo32` (not 64)
- RPATH strings: compute offset as `lc.offset + rpath.path as usize`
- `seg.sections()` yields `(Section, &[u8])` tuples directly

## Development Patterns
1. **Parallel analysis**: Use `rayon` for independent checks (binary, manifests, patterns)
2. **Error handling**: Return `Result<T>` with context; CLI exits with code 1 on high findings
3. **Tracing**: Use `tracing::info!`, `debug!` for audit log entries; `--verbose` for timing
4. **Rules**: Load YAML via serde_yaml; RegexSet for efficient multi-pattern scanning
5. **Secrets**: Deduplicate matches; high severity for known patterns (AWS, GCP, Azure, etc.)

## Important Notes
- Minimum severity filter (--min-severity) in main.rs, not lib.rs
- HTML reports embed Tera template at compile-time via `include_str!`
- Network domain intel only runs with `--network` flag (no default DNS/geolocation)
- Audit log tracks scan phases; visible with `--verbose`
- Exit code: 0 (all secure), 1 (high findings), 2 (scan error)

## Testing
- Use `tempfile` for IPA/APK fixtures in tests
- Criterion benchmarks in benches/ (not yet added)
- Manual testing: `cargo run -- path/to/app.ipa --format json -v`
