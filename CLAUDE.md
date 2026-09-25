# Pavise Development Guide

## Overview

Fast iOS IPA static security analyzer

## Project Structure

- **src/main.rs**: CLI (clap); scans IPAs only (`.apk` is rejected with exit 2)
- **src/lib.rs**: Orchestrator; `scan_ipa()` entry point
- **src/unpacker/**: ZIP extraction, binary location, hashing
- **src/manifest/**: Info.plist, entitlements, privacy manifest, provisioning profile parsing
- **src/binary/**: Mach-O parsing (goblin 0.8), symbols, `__ustring`/ObjC class names
- **src/patterns/**: Regex scanning (secrets, trackers, URLs, emails)
- **src/resources/**: Firebase config, cert classification, SCA
- **src/scoring/**: severity × class scoring (`owasp.rs`); single rule-ID → OWASP 2024 / MASVS v2 table (`mapping.rs`)
- **src/report/**: JSON, SARIF 2.1.0, HTML (Tera), PDF (brief summary: own template `report.pdf.tera` printed by headless Chrome — needs Chrome/Chromium; see [PDF docs](docs/pdf-report.md))
- **src/server/**: axum web server (`build_router`, handlers, proxy-aware rate limit, caps); `src/serve.rs` is startup only — see [server docs](docs/server.md)
- **src/network/**: DNS + offline IP2Location GeoIP, OSV.dev CVE lookup, Firebase open-backend probes (--network flag)
- **rules/**: YAML rule files, embedded at build time (`src/rules.rs`); `--rules DIR` replaces them

## Benchmarks

- [MobSF comparison](docs/mobsf-comparison.md): performance + accuracy vs MobSF on DVIA/Navic/VLC (2026-05-22)
- [EOL library detection](docs/eol-data.md): banner-based library versions, endoflife.date snapshots in `data/eol/`, weekly refresh (2026-09-25)
- [Finding attribution](docs/finding-attribution.md): library-vs-app API severity, URL/domain noise, OpenSSL EOL, sideload context (2026-09-25)

## Plans

- [Backend remediation plan](docs/remediation-plan.md): scoring, false positives, server hardening, gaps (2026-09-24)
- [Railway deploy](docs/deploy-railway.md): config, env sizing, CPU/memory measurements (2026-09-25)

## Development Patterns

1. **Parallel**: Use `rayon` for independent checks
2. **Error handling**: Return `Result<T>` with context; exit code 1 on high findings, 2 on error
3. **Tracing**: `tracing::info!`, `debug!` for audit logs; `--verbose` shows timing
4. **Rules**: Load YAML via serde_yaml; no RegexSet over Unicode patterns on binary text (see [perf notes](docs/deploy-railway.md#performance-pitfalls))
5. **Memory**: `UnpackedArchive::read` inflates lazily; only plists/profiles/lockfiles + main binary stay in RAM

## Agent Rules

- Keep any documentation under 100 lines
- Store any docs in docs/ and reference them in CLAUDE.md
- If you solve big/rare/persistent problems that might come up again, document it
- Don't cheat in test-cases
- cargo check/build/test code changes
- Your code will be reviewed by Codex
