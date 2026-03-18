# Pavise Distribution & Integration Plan

## Phase 1: Foundation (Ship the Binary)

### 1.1 GitHub Release Workflow

- [x] Add `.github/workflows/release.yml` triggered on version tags (`v*`)
- [x] Cross-compile targets: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`
- [ ] Use `cross` or `cargo-zigbuild` for Linux cross-compilation from CI
- [x] Package each target as `pavise-<target>.tar.gz` with the binary + LICENSE
- [x] Upload artifacts to GitHub Releases via `softprops/action-gh-release`
- [x] Add install script: `curl -fsSL https://raw.githubusercontent.com/<owner>/pavise/main/install.sh | sh`

### 1.2 Publish to crates.io

- [x] Verify `Cargo.toml` metadata (repository, homepage, keywords, categories)
- [x] Add `readme = "README.md"` and `exclude` patterns for test fixtures
- [ ] `cargo publish --dry-run` to validate
- [ ] Publish: `cargo publish`

### 1.3 Docker Image Publishing

- [x] Add `.github/workflows/docker.yml` triggered on tags and main pushes
- [x] Build and push to GitHub Container Registry (`ghcr.io/<owner>/pavise`)
- [x] Tag images as `latest`, `<version>`, and `<sha>`
- [x] Add `org.opencontainers.image.*` labels to Dockerfile

## Phase 2: CI/CD Pipeline Integration

### 2.1 GitHub Action

- [x] Create `pavise-action` repo (or `action.yml` in this repo under `.github/actions/pavise/`)
- [x] Action inputs: `ipa-path`, `format` (json/sarif/html), `min-severity`, `fail-on`
- [x] Action pulls prebuilt binary from GitHub Releases (or Docker image)
- [x] Outputs: `score`, `grade`, `findings-count`, `report-path`
- [x] Exit code 1 when findings exceed `fail-on` threshold
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

- [x] Create `gitlab-ci-template.yml` in repo root or `ci/` directory
- [x] Uses Docker image from GHCR
- [x] Produces JSON/SARIF artifact
- [x] Configurable severity threshold via CI variables

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
