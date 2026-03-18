# Test Coverage Plan

Current state: 38 unit tests + 77 integration tests (115 total). This document outlines what needs to be added for production-grade coverage.

## 1. Malformed Input Tests (High Priority)

### ZIP/IPA Handling
- [x] Truncated ZIP file (incomplete central directory)
- [x] ZIP with zero entries
- [x] ZIP with entry names containing `..` (path traversal)
- [x] ZIP with absolute path entries (leading `/`)
- [x] ZIP with extremely long entry names (>4096 chars)
- [x] ZIP bomb (deeply nested or high compression ratio)
- [x] ZIP entry claiming size > `MAX_IN_MEMORY` (512 MB) — covered by unpacker's skip logic
- [x] ZIP entry with mismatched declared vs actual size
- [x] Non-ZIP file with `.ipa` extension
- [x] Valid ZIP but missing `Payload/` directory structure
- [x] IPA with multiple `Info.plist` at different depths

### Mach-O Parsing
- [x] Truncated Mach-O header (fewer bytes than header size)
- [x] Invalid magic number
- [x] Fat binary with zero architectures
- [x] Fat binary with invalid architecture offsets
- [x] Mach-O with random garbage after valid magic (load command past EOF)
- [x] Mach-O with invalid symbol table offsets
- [x] Mach-O with corrupt LC_CODE_SIGNATURE
- [x] Mach-O with overlapping segments
- [x] 32-bit only Mach-O (ARMv7)
- [x] Empty data (zero bytes)

## 2. Boundary Condition Tests (High Priority)

- [ ] File at exactly `MAX_IN_MEMORY` (512 MB) boundary
- [ ] File at exactly `MAX_TOTAL_EXTRACTED` (2 GiB) boundary
- [x] IPA with exactly 0 bytes of extractable content (only directories)
- [x] Empty `Info.plist` (valid XML/binary plist, no keys)
- [x] `Info.plist` missing `CFBundleExecutable`
- [x] Score computation with all-High findings (should floor near 0)
- [x] Score computation with zero findings (should be 100)
- [x] Entropy detection at exact threshold values (5.0, 5.7)
- [x] Extract printable strings: all binary data
- [x] Extract printable strings: exact min_len boundary
- [x] Extract printable strings: one below min_len
- [x] Score deterministic (same input = same score)
- [x] Framework canary deduction capped at 8
- [x] Framework ARC deduction capped at 15

## 3. Network Failure Tests (Medium Priority)

- [ ] DNS resolution timeout
- [ ] ip-api.com returning HTTP 429 (rate limited)
- [ ] ip-api.com returning malformed JSON
- [ ] ip-api.com returning HTTP 500
- [ ] Network unreachable when `--network` is enabled
- [ ] Domain with no DNS records

## 4. Pattern Engine Tests (Medium Priority)

- [x] YAML rules file with invalid regex (should error gracefully)
- [x] YAML rules file with zero rules (should scan without crashing)
- [x] Regex patterns with very large input (>1 MB of printable strings)
- [x] Pattern scan with empty input
- [x] Secret deduplication with 1,000 identical matches → 1
- [x] Secret deduplication with 100 distinct matches → 100
- [x] Tracker detection loads and handles empty inputs
- [x] Tracker detection by domain
- [x] Email extraction with 100+ emails in a single file
- [x] Email extraction no false positives in code patterns
- [x] Noise file detection for various binary extensions
- [x] Cipher detection: DES, 3DES, RC4, ECB, multiple, clean text
- [x] URL noise patterns not flagged as HTTP findings
- [x] URL domain deduplication
- [x] Entropy false positive filters: URLs, dotted identifiers, Swift/ObjC symbols
- [x] Symbol scanner loads and handles empty/large import lists

## 5. Report Generation Tests (Medium Priority)

- [x] JSON output round-trips through `serde_json` (serialize then deserialize)
- [x] SARIF output is valid JSON with required 2.1.0 fields
- [x] SARIF contains all finding IDs from the scan
- [x] SARIF truncates secrets to 40 chars
- [x] SARIF includes CWE relationships
- [x] HTML output contains all finding IDs from the scan
- [x] HTML generation with very large reports (100+ findings)
- [x] Baseline diff with identical reports (zero delta)
- [x] Baseline diff with completely different reports
- [x] Baseline diff empty vs findings (both directions)

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
- [x] Ensure score is deterministic (same input = same score across runs)

## Implementation Notes

- Use `tempfile` crate for creating test fixtures (already a dev dependency)
- For Mach-O fixtures, consider using `object` crate to programmatically generate minimal binaries
- Fuzzing should be added as a separate CI job (runs nightly, not on every PR)
- Consider `proptest` for property-based testing of the scoring algorithm
