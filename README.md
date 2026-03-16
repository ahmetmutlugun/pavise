# Pavise

Fast static security analysis for iOS and Android mobile apps. Scans IPA/APK files in <3 seconds with coverage comparable to MobSF.

## Features

- **iOS IPA Analysis** (production-ready)
  - Binary protections: NX, PIE, encryption, RPATH
  - Manifest analysis: Info.plist, entitlements, provisioning profiles
  - API usage: 15+ dangerous iOS APIs
  - Permissions: Keychain, HealthKit, location, camera, contacts, etc.
  - URL schemes: generic scheme detection

- **Secret Detection** (23 patterns)
  - AWS, GCP, Azure, GitHub, Stripe, Slack, Mapbox, Twilio, OpenAI, Anthropic, etc.
  - Scans strings, binary symbols, and metadata files

- **Tracker Detection**
  - 30+ advertising/analytics libraries (Firebase, Crashlytics, Flurry, etc.)

- **Supply Chain Analysis**
  - Framework inventory with versions
  - Dependency tracking

- **Network Intelligence** (optional `--network`)
  - DNS resolution and geolocation via ip-api.com
  - OFAC sanctions checking

- **Multiple Report Formats**
  - JSON (full details)
  - SARIF 2.1.0 (IDE integration)
  - HTML (self-contained dark theme)

## Installation

```bash
cargo build --release
./target/release/pavise --help
```

## Usage

### Basic scan (JSON output to console)
```bash
pavise app.ipa
```

### Save JSON report
```bash
pavise app.ipa -o report.json
```

### HTML report
```bash
pavise app.ipa --format html -o report.html
```

### SARIF (for IDE integration)
```bash
pavise app.ipa --format sarif -o report.sarif
```

### Network intelligence (DNS + geolocation)
```bash
pavise app.ipa --network
```

### Filter to high-severity findings only
```bash
pavise app.ipa --min-severity high
```

### Quiet mode (score line only)
```bash
pavise app.ipa --quiet
```

### Verbose (timing breakdown)
```bash
pavise app.ipa --verbose
```

### Custom rules directory
```bash
pavise app.ipa --rules ./my-rules/
```

## Output

### Console (stderr)
- Security score (0-100) and grade (A-F)
- High/warning/info finding counts
- File hashes (MD5, SHA256)
- Binary protections status
- Detected trackers
- Top 10 secrets (truncated)
- Domain intelligence (if --network used)
- Audit log (if --verbose used)

### Exit Codes
- **0**: Scan successful, no high-severity findings
- **1**: Scan successful, high-severity findings detected
- **2**: Scan failed (invalid input, parsing error)

## Rules Format

Rules are YAML files in `rules/` directory. Example:

```yaml
rules:
  - id: QS-SECRET-001
    name: AWS Access Key
    type: secret
    severity: high
    patterns:
      - "AKIA[0-9A-Z]{16}"
```

## Performance

- **Typical IPA scan**: 500ms – 1s (depends on app size)
- **Release build size**: ~3MB (stripped, LTO)
- **Memory**: ~100-200MB (in-memory IPA extraction)

## Architecture Highlights

- **Parallel analysis**: Binary protections, manifests, and pattern scanning run in parallel (rayon)
- **Zero-copy strings**: Printable ASCII extraction from binaries without allocating every match
- **Efficient regex**: Single-pass RegexSet for multi-pattern scanning
- **Streaming ZIP**: In-memory unzipping with on-demand framework extraction

## Roadmap

- **Phase 2**: Android APK binary manifest parsing, ELF binary analysis
- **Phase 3**: Expanded rules, HIPAA compliance checks, entitlement validation

## License

MIT
