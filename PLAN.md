# Pavise Distribution & Integration Plan

## Phase 1: Foundation (Ship the Binary)

### 1.1 GitHub Release Workflow

- [ ] Add `.github/workflows/release.yml` triggered on version tags (`v*`)
- [ ] Cross-compile targets: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`
- [ ] Use `cross` or `cargo-zigbuild` for Linux cross-compilation from CI
- [ ] Package each target as `pavise-<target>.tar.gz` with the binary + LICENSE
- [ ] Upload artifacts to GitHub Releases via `softprops/action-gh-release`
- [ ] Add install script: `curl -fsSL https://raw.githubusercontent.com/<owner>/pavise/main/install.sh | sh`

### 1.2 Publish to crates.io

- [ ] Verify `Cargo.toml` metadata (repository, homepage, keywords, categories)
- [ ] Add `readme = "README.md"` and `exclude` patterns for test fixtures
- [ ] `cargo publish --dry-run` to validate
- [ ] Publish: `cargo publish`

### 1.3 Docker Image Publishing

- [ ] Add `.github/workflows/docker.yml` triggered on tags and main pushes
- [ ] Build and push to GitHub Container Registry (`ghcr.io/<owner>/pavise`)
- [ ] Tag images as `latest`, `<version>`, and `<sha>`
- [ ] Add `org.opencontainers.image.*` labels to Dockerfile

## Phase 2: CI/CD Pipeline Integration

### 2.1 GitHub Action

- [ ] Create `pavise-action` repo (or `action.yml` in this repo under `.github/actions/pavise/`)
- [ ] Action inputs: `ipa-path`, `format` (json/sarif/html), `min-severity`, `fail-on`
- [ ] Action pulls prebuilt binary from GitHub Releases (or Docker image)
- [ ] Outputs: `score`, `grade`, `findings-count`, `report-path`
- [ ] Exit code 1 when findings exceed `fail-on` threshold
- [ ] Add example workflow in README

### 2.2 SARIF / GitHub Code Scanning

- [ ] Document SARIF upload integration in README:
  ```yaml
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: pavise-report.sarif
  ```
- [ ] Validate SARIF output against the 2.1.0 schema with `sarif-tools`
- [ ] Ensure `ruleId`, `level`, `location` fields map correctly to GitHub Security tab
- [ ] Add SARIF output as default in the GitHub Action

### 2.3 GitLab CI Template

- [ ] Create `gitlab-ci-template.yml` in repo root or `ci/` directory
- [ ] Uses Docker image from GHCR
- [ ] Produces JSON/SARIF artifact
- [ ] Configurable severity threshold via CI variables

### 2.4 Fastlane Plugin

- [ ] Create `fastlane-plugin-pavise` Ruby gem (separate repo)
- [ ] Action: `pavise(ipa_path:, min_severity:, format:)`
- [ ] Downloads platform binary on first run, caches in `~/.pavise/bin/`
- [ ] Returns parsed findings hash for lane conditionals
- [ ] Publish to RubyGems

## Phase 3: Try It / Demo

### 3.1 Hosted Web Demo

- [ ] Deploy `pavise-server` Docker image to Fly.io or Railway
- [ ] Add rate limiting (e.g., 10 scans/hour per IP)
- [ ] Cap upload size (100MB)
- [ ] Add landing page with drag-and-drop upload
- [ ] Auto-delete uploaded IPAs after scan completes
- [ ] Add example report page with a sample scan

### 3.2 Homebrew Tap

- [ ] Create `homebrew-tap` repo (`<owner>/homebrew-tap`)
- [ ] Add formula that downloads the correct binary from GitHub Releases
- [ ] `brew install <owner>/tap/pavise`
- [ ] Update formula automatically via release workflow

## Phase 4: Extended Reach

### 4.1 npm Wrapper (Optional)

- [ ] Create `pavise` npm package (separate repo or `packages/npm/`)
- [ ] `postinstall` script downloads platform-specific binary
- [ ] Exposes `npx pavise scan app.ipa` CLI
- [ ] Publish to npm registry

### 4.2 Bitrise Step (Optional)

- [ ] Create Bitrise step definition (`step.yml`)
- [ ] Submit to Bitrise StepLib
- [ ] Uses Docker image or downloads binary

### 4.3 VS Code Extension (Optional)

- [ ] Right-click IPA in explorer to scan
- [ ] Render HTML report in webview panel
- [ ] Show findings as VS Code diagnostics

## Priority Order

| Order | Item                    | Effort | Impact | Dependency             |
| ----- | ----------------------- | ------ | ------ | ---------------------- |
| 1     | GitHub Release Workflow | S      | High   | None                   |
| 2     | crates.io Publish       | S      | Medium | Cargo.toml cleanup     |
| 3     | Docker Image Publishing | S      | Medium | Dockerfile exists      |
| 4     | GitHub Action           | M      | High   | Release workflow       |
| 5     | SARIF Integration Docs  | S      | High   | SARIF output exists    |
| 6     | Hosted Web Demo         | M      | High   | Docker image published |
| 7     | Homebrew Tap            | S      | Medium | Release workflow       |
| 8     | GitLab CI Template      | S      | Medium | Docker image published |
| 9     | Fastlane Plugin         | M      | Medium | Release workflow       |
| 10    | npm Wrapper             | M      | Low    | Release workflow       |

## Notes

- S = Small (< 1 day), M = Medium (1-3 days), L = Large (3+ days)
- Phase 1 unblocks everything else — ship binaries first
- SARIF support already exists, so GitHub Code Scanning is low-hanging fruit
- Hosted demo is the best "try before you integrate" channel

Feature plan:

1. Weak/Insecure Encryption — not checked at all

- id: QS-API-016
  title: "Use of DES/3DES encryption (weak cipher)"
  symbols: [_kCCAlgorithmDES, _kCCAlgorithm3DES]
  severity: high
  cwe: "CWE-327"
  owasp_masvs: "MSTG-CRYPTO-4"

- id: QS-API-017
  title: "ECB mode encryption (insecure block cipher mode)"
  symbols: [_kCCOptionECBMode]
  severity: high
  cwe: "CWE-327"
  owasp_masvs: "MSTG-CRYPTO-3"

2. CoreData without encryption — you detect SQLite (QS-API-009) but not CoreData

- id: QS-API-018
  title: "CoreData persistent store (verify encryption)"
  symbols: [_NSPersistentStoreCoordinator, _NSPersistentContainer]
  severity: info
  cwe: "CWE-312"
  owasp_masvs: "MSTG-STORAGE-1"

3. Realm database usage — bundled .realm files are detected, but symbol-level isn't

- id: QS-API-019
  title: "Realm database usage (verify encryption)"
  symbols: [_RLMRealm, _RLMRealmConfiguration]
  severity: info
  cwe: "CWE-312"
  owasp_masvs: "MSTG-STORAGE-1"

4. SSL/TLS validation bypass — IPA Auditor checks for this, Pavise doesn't

- id: QS-API-020
  title: "SSL/TLS certificate validation bypass"
  symbols: - _SecTrustSetExceptions - \_SecTrustEvaluateWithError # paired with ignore: look for pattern
  severity: high
  cwe: "CWE-295"
  owasp_masvs: "MSTG-NETWORK-3"
  Note: The more accurate check here is a regex pattern for URLSession(_:didReceive:completionHandler:) with completionHandler(.useCredential, ...) in strings — that would go in a new patterns/ rule rather than a symbol.

5. WKWebView JavaScript enabled — UIWebView is detected (QS-API-015) but WKWebView JS config isn't

- id: QS-API-021
  title: "WKWebView with JavaScript enabled (check for untrusted content)"
  symbols:
  - \_WKWebViewConfiguration
  - \_WKPreferences
    severity: info
    cwe: "CWE-79"
    owasp_masvs: "MSTG-PLATFORM-5"

6. Plist file write to unprotected location

- id: QS-API-022
  title: "Plist written to unprotected file path"
  symbols:
  - \_writeToFile:atomically:
    severity: info
    cwe: "CWE-312"
    owasp_masvs: "MSTG-STORAGE-1"

7. SSL pinning detection — currently Pavise doesn't tell you whether pinning is implemented (only absence is implied)

- id: QS-API-023
  title: "SSL certificate pinning present"
  symbols:
  - \_SecTrustSetAnchorCertificates
  - \_SecCertificateCreateWithData
  - \_TrustKit # TrustKit framework
    severity: info # informational — good signal
    owasp_masvs: "MSTG-NETWORK-4"
