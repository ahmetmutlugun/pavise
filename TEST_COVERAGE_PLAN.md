# Test Coverage Plan

Current state: 37 unit tests + 2 integration tests. This document outlines what needs to be added for production-grade coverage.

## 1. Malformed Input Tests (High Priority)

### ZIP/IPA Handling
- [ ] Truncated ZIP file (incomplete central directory)
- [ ] ZIP with zero entries
- [ ] ZIP with entry names containing `..` (path traversal)
- [ ] ZIP with absolute path entries (leading `/`)
- [ ] ZIP with extremely long entry names (>4096 chars)
- [ ] ZIP bomb (deeply nested or high compression ratio)
- [ ] ZIP entry claiming size > `MAX_IN_MEMORY` (50 MB)
- [ ] ZIP entry with mismatched declared vs actual size
- [ ] Non-ZIP file with `.ipa` extension
- [ ] Valid ZIP but missing `Payload/` directory structure
- [ ] IPA with multiple `Info.plist` at different depths

### Mach-O Parsing
- [ ] Truncated Mach-O header (fewer bytes than header size)
- [ ] Invalid magic number
- [ ] Fat binary with zero architectures
- [ ] Fat binary with invalid architecture offsets
- [ ] Mach-O with load command offset past end of file
- [ ] Mach-O with invalid symbol table offsets
- [ ] Mach-O with corrupt LC_CODE_SIGNATURE
- [ ] Mach-O with overlapping segments
- [ ] 32-bit only Mach-O (ARMv7)

## 2. Boundary Condition Tests (High Priority)

- [ ] File at exactly `MAX_IN_MEMORY` (50 MB) boundary
- [ ] File at exactly `MAX_FILE_BYTES` (2 GiB) boundary
- [ ] IPA with exactly 0 bytes of extractable content
- [ ] Empty `Info.plist` (valid XML/binary plist, no keys)
- [ ] `Info.plist` missing `CFBundleExecutable`
- [ ] Score computation with all-High findings (should be 0)
- [ ] Score computation with zero findings (should be 100)
- [ ] Entropy detection at exact threshold values (5.0, 5.7)

## 3. Network Failure Tests (Medium Priority)

- [ ] DNS resolution timeout
- [ ] ip-api.com returning HTTP 429 (rate limited)
- [ ] ip-api.com returning malformed JSON
- [ ] ip-api.com returning HTTP 500
- [ ] Network unreachable when `--network` is enabled
- [ ] Domain with no DNS records

## 4. Pattern Engine Tests (Medium Priority)

- [ ] YAML rules file with invalid regex (should error gracefully)
- [ ] YAML rules file with zero rules (should scan without crashing)
- [ ] Regex patterns with very large input (>1 MB of printable strings)
- [ ] Secret deduplication with 10,000+ matches
- [ ] Tracker detection with overlapping domain/framework matches
- [ ] Email extraction with 1000+ emails in a single file

## 5. Report Generation Tests (Medium Priority)

- [ ] JSON output round-trips through `serde_json` (serialize then deserialize)
- [ ] SARIF output validates against SARIF 2.1.0 schema
- [ ] HTML output contains all finding IDs from the scan
- [ ] PDF generation with very large reports (100+ findings)
- [ ] Baseline diff with identical reports (zero delta)
- [ ] Baseline diff with completely different reports

## 6. Server Mode Tests (Medium Priority)

- [ ] Upload non-IPA file via multipart
- [ ] Upload file exceeding 512 MB body limit
- [ ] Concurrent uploads at `MAX_CONCURRENT_SCANS` limit
- [ ] Request scan result for non-existent ID
- [ ] Result TTL expiration (1 hour)
- [ ] PDF download for a completed scan

## 7. Fuzzing (High Priority)

Recommended setup using `cargo-fuzz`:

```
cargo fuzz init
```

### Fuzz Targets
- [ ] `fuzz_zip_unpack`: Feed arbitrary bytes to `unpacker::ipa::unpack()`
- [ ] `fuzz_macho_parse`: Feed arbitrary bytes to `binary::macho::analyze()`
- [ ] `fuzz_plist_parse`: Feed arbitrary bytes to `manifest::info_plist::analyze()`
- [ ] `fuzz_pattern_scan`: Feed arbitrary strings to `PatternEngine::scan()`
- [ ] `fuzz_entropy`: Feed arbitrary strings to `entropy::scan_for_high_entropy()`

Each target should run for at least 1 hour on CI or until 1M iterations without panics.

## 8. Regression Tests

- [ ] Add a test IPA fixture with known findings; assert exact finding IDs and count
- [ ] Add a "golden file" test: scan a fixture, compare JSON output to a snapshot
- [ ] Ensure score is deterministic (same input = same score across runs)

## Implementation Notes

- Use `tempfile` crate for creating test fixtures (already a dev dependency)
- For Mach-O fixtures, consider using `object` crate to programmatically generate minimal binaries
- Fuzzing should be added as a separate CI job (runs nightly, not on every PR)
- Consider `proptest` for property-based testing of the scoring algorithm
