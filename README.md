# Pavise

Fast static security analysis for iOS IPA files. Scans apps in under 3 seconds with coverage comparable to MobSF.

## Features

- **Binary protections** — NX, PIE, ARC, encryption, RPATH, stack canaries
- **Manifest analysis** — Info.plist, entitlements, provisioning profiles
- **Secret detection** — 23 patterns (AWS, GCP, Azure, GitHub, Stripe, Slack, OpenAI, etc.)
- **Dangerous API usage** — 15+ risky iOS APIs (strcpy, NSLog, malloc, etc.)
- **Tracker detection** — 30+ advertising/analytics SDKs (Firebase, Crashlytics, Flurry, etc.)
- **Supply chain analysis** — framework inventory with version tracking
- **Network intelligence** — DNS resolution and IP geolocation (opt-in `--network`)
- **Multiple output formats** — JSON, SARIF 2.1.0, HTML, PDF
- **Baseline diffing** — compare scans to track regressions with `--baseline`
- **OWASP-based scoring** — 0–100 score with A–F grading

## Installation

### From source

```bash
cargo install pavise
```

### Pre-built binaries

```bash
curl -fsSL https://raw.githubusercontent.com/ahmetmutlugun/pavise/main/install.sh | sh
```

### Docker

```bash
docker pull ghcr.io/ahmetmutlugun/pavise:latest
docker run --rm -v "$PWD:/work" ghcr.io/ahmetmutlugun/pavise pavise /work/app.ipa
```

## Usage

```bash
# Basic scan (JSON to stdout)
pavise app.ipa

# Save report to file
pavise app.ipa -o report.json

# HTML report
pavise app.ipa --format html -o report.html

# PDF report
pavise app.ipa --format pdf -o report.pdf

# SARIF for IDE / GitHub Code Scanning
pavise app.ipa --format sarif -o report.sarif

# Network intelligence (DNS + geolocation)
pavise app.ipa --network

# Filter by severity
pavise app.ipa --min-severity high

# Compare against a previous scan
pavise app.ipa --baseline previous-report.json

# Explain a specific finding
pavise app.ipa --explain QS-BIN-001

# Quiet mode (score line only)
pavise app.ipa --quiet

# Verbose (timing breakdown)
pavise app.ipa --verbose
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No high-severity findings |
| 1 | High-severity findings detected |
| 2 | Scan error (invalid input, parse failure) |

## CI/CD Integration

### GitHub Actions

```yaml
- uses: ahmetmutlugun/pavise/.github/actions/pavise@main
  with:
    ipa-path: build/App.ipa
    format: sarif
    fail-on: high
```

Upload SARIF results to GitHub's Security tab:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pavise-report.sarif
```

## Custom Rules

Rules are YAML files in the `rules/` directory:

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

## Performance

- **Scan time**: 500ms–1s (depends on app size)
- **Binary size**: ~3 MB (stripped, LTO)
- **Memory**: ~100–200 MB (in-memory extraction)

Parallel analysis via rayon, single-pass RegexSet scanning, and zero-copy string extraction keep things fast.

## License

MIT
