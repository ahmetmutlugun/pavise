# Pavise Development Guide

## Overview

Fast iOS IPA static security analyzer

## Project Structure

- **src/main.rs**: CLI (clap) with IPA/APK dispatch
- **src/lib.rs**: Orchestrator; `scan_ipa()` entry point
- **src/unpacker/**: ZIP extraction, binary location, hashing
- **src/manifest/**: Info.plist, entitlements, provisioning profile parsing
- **src/binary/**: Mach-O/ELF parsing (goblin 0.8), symbol extraction
- **src/patterns/**: Regex scanning (secrets, trackers, URLs, emails)
- **src/resources/**: Firebase config, ATS/network security, SCA
- **src/scoring/**: OWASP-based scoring and grading
- **src/report/**: JSON, SARIF 2.1.0, HTML Tera output
- **src/network/**: DNS via ip-api.com (--network flag)
- **rules/**: YAML files

## Development Patterns

1. **Parallel**: Use `rayon` for independent checks
2. **Error handling**: Return `Result<T>` with context; exit code 1 on high findings, 2 on error
3. **Tracing**: `tracing::info!`, `debug!` for audit logs; `--verbose` shows timing
4. **Rules**: Load YAML via serde_yaml; RegexSet for multi-pattern scanning

## Agent Rules

- Keep any documentation under 100 lines
- Store any docs in docs/ and reference them in CLAUDE.md
- If you solve big/rare/persistent problems that might come up again, document it
- Don't cheat in test-cases
- cargo check/build/test code changes
- Your code will be reviewed by Codex
