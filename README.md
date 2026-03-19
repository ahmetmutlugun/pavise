# Pavise

[![Crates.io](https://img.shields.io/crates/v/pavise)](https://crates.io/crates/pavise)
[![License: MPL-2.0](https://img.shields.io/crates/l/pavise)](LICENSE)
[![CI](https://github.com/ahmetmutlugun/pavise/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmetmutlugun/pavise/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io/ahmetmutlugun/pavise)

Fast static security analysis for iOS IPA files. Sub-second scans with comprehensive coverage.

## Quick Start

```bash
# Install
cargo install pavise

# Scan
pavise app.ipa

# HTML report
pavise app.ipa --format html -o report.html
```

Or use Docker:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/ahmetmutlugun/pavise pavise /work/app.ipa
```

## What It Checks

| Category | Examples |
|----------|----------|
| Binary protections | NX, PIE, ARC, encryption, RPATH, stack canaries |
| Manifest analysis | Info.plist, entitlements, provisioning profiles |
| Secret detection | 23 patterns — AWS, GCP, Azure, GitHub, Stripe, Slack, OpenAI, etc. |
| Dangerous APIs | 15+ risky iOS APIs (strcpy, NSLog, malloc, etc.) |
| Tracker detection | 30+ advertising/analytics SDKs |
| Supply chain | Framework inventory with version tracking |
| Network intel | DNS resolution and IP geolocation (`--network`) |

## Output Formats

JSON (default), SARIF 2.1.0, HTML, and PDF. OWASP-based 0–100 scoring with A–F grades.

```bash
pavise app.ipa --format sarif -o report.sarif   # IDE / GitHub Code Scanning
pavise app.ipa --format pdf -o report.pdf
pavise app.ipa --baseline previous.json          # Diff against previous scan
pavise app.ipa --min-severity high               # Filter by severity
pavise app.ipa --explain QS-BIN-001              # Explain a finding
pavise app.ipa --quiet                           # Score line only
```

## CI/CD

```yaml
- uses: ahmetmutlugun/pavise/.github/actions/pavise@main
  with:
    ipa-path: build/App.ipa
    format: sarif
    fail-on: high
```

Exit codes: `0` clean, `1` high-severity findings, `2` scan error.

## Custom Rules

```yaml
rules:
  - id: QS-SECRET-001
    name: AWS Access Key
    type: secret
    severity: high
    patterns:
      - "AKIA[0-9A-Z]{16}"
```

Pass a custom rules directory with `--rules ./my-rules/`.

## License

[MPL-2.0](LICENSE)
