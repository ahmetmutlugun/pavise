# Pavise

<!-- Crates.io badge disabled: the `pavise` crate name belongs to someone else (a 0.0.1
     placeholder). Re-enable with the new crate name once it is published.
[![Crates.io](https://img.shields.io/crates/v/pavise)](https://crates.io/crates/pavise)
-->
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)
[![CI](https://github.com/ahmetmutlugun/pavise/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmetmutlugun/pavise/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io/ahmetmutlugun/pavise)

Fast static security analysis for iOS IPA files. Sub-second scans with comprehensive coverage.

## Quick Start

```bash
# Install (Rust 1.75+; builds in about a minute)
cargo install --locked --git https://github.com/ahmetmutlugun/pavise --bin pavise

# Scan
pavise app.ipa

# HTML report
pavise app.ipa --format html -o report.html
```

Or build from a checkout: `cargo build --release`, then run `target/release/pavise`.
PDF output (`--format pdf`) needs Chrome or Chromium installed.

Or use Docker (linux/amd64 and linux/arm64; the image also serves the web UI by default):

```bash
docker run --rm -v "$PWD:/work" ghcr.io/ahmetmutlugun/pavise pavise /work/app.ipa
```

## What It Checks

| Category | Examples |
|----------|----------|
| Binary protections | NX, PIE, ARC, encryption, RPATH, stack canaries |
| Manifest analysis | Info.plist, entitlements, provisioning profiles |
| Secret detection | 29 patterns — AWS, GCP, Azure, GitHub, Stripe, Slack, OpenAI, etc. |
| Dangerous APIs | 15+ risky iOS APIs (strcpy, NSLog, malloc, etc.) |
| Tracker detection | 20 advertising/analytics SDKs |
| Supply chain | Framework inventory; end-of-life detection for OpenSSL, FFmpeg, Qt, Unity, Python, jQuery and more ([endoflife.date](https://endoflife.date) data) |
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

The default rules in `rules/` (`secrets.yaml`, `ios_apis.yaml`, `trackers.yaml`, `permissions.yaml`) are
compiled into the binary. `--rules DIR` replaces the whole set, so copy all four files and edit them; a
missing or unparseable file is a scan error (exit 2). Secret rules look like:

```yaml
- id: QS-SEC-002
  title: "AWS Access Key ID"
  pattern: "AKIA[0-9A-Z]{16}"
  severity: high          # high | warning | info
  category: secrets
```

## License

[MPL-2.0](LICENSE)
