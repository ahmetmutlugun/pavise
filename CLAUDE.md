# Pavise Development Guide

## Overview
Fast iOS IPA static security analyzer (target: <3s scan time). Phase 1 MVP complete; Phase 2 (Android APK, ELF) and Phase 3 are stubs.

## Project Structure
- **src/main.rs**: CLI (clap) with IPA/APK dispatch
- **src/lib.rs**: Orchestrator; `scan_ipa()` entry point
- **src/unpacker/**: ZIP extraction, binary location, hashing
- **src/manifest/**: Info.plist, entitlements, provisioning profile parsing
- **src/binary/**: Mach-O/ELF parsing (goblin 0.8), symbol extraction
- **src/patterns/**: Regex scanning (secrets, trackers, URLs, emails)
- **src/resources/**: Firebase config, ATS/network security, SCA
- **src/scoring/**: OWASP-based 0-100 scoring with A-F grading
- **src/report/**: JSON, SARIF 2.1.0, HTML Tera template output
- **src/network/**: DNS/geolocation via ip-api.com (--network flag only)
- **rules/**: YAML rule files (secrets, ios_apis, permissions, trackers)

## Key goblin 0.8 Quirks
- Fat binaries: `Mach::Fat(fat)` → `fat.get(i)?` returns `SingleArch`
- `macho.data` is private — pass raw `&[u8]` separately
- Encryption: `CommandVariant::EncryptionInfo32` (not 64)
- RPATH: offset = `lc.offset + rpath.path as usize`
- `seg.sections()` yields `(Section, &[u8])` tuples directly

## Development Patterns
1. **Parallel**: Use `rayon` for independent checks
2. **Error handling**: Return `Result<T>` with context; exit code 1 on high findings, 2 on error
3. **Tracing**: `tracing::info!`, `debug!` for audit logs; `--verbose` shows timing
4. **Rules**: Load YAML via serde_yaml; RegexSet for multi-pattern scanning
5. **Secrets**: Deduplicate; high severity for AWS, GCP, Azure patterns

## Important Notes
- Min severity filter (--min-severity) in main.rs, not lib.rs
- HTML reports embed Tera template at compile-time
- Network intel only with --network flag
- Exit codes: 0 (secure), 1 (high findings), 2 (error)
- Testing: Use `tempfile` for fixtures; manual: `cargo run -- app.ipa --format json -v`
