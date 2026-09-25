# Deferred Detection Gaps

Rules that miss real behaviour in compiled binaries. All were found by the private
`pavise-testapps` suite (known_gaps in its `expect/*.yaml`). Each fix is larger than a
regex or list change. Recorded 2026-09-25.

## 1. CommonCrypto ciphers: QS-CRYPTO-001…006 (DVIA-NG)

**Problem.** `src/patterns/ciphers.rs` looks for the text `kCCAlgorithmDES`,
`kCCOptionECBMode` and similar. These are C enum constants that compile to integer
immediates, so the names never appear in a built binary. The rules only fire on bundled
headers or source. `CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, …)` goes unseen.
OpenSSL/BoringSSL ciphers are already covered by import name (QS-API-016 DES/3DES,
QS-API-017 ECB).

**Fix: arm64 call-site argument analysis** (a new `src/binary/callsites.rs`):
1. Map `__stubs` entries to symbols using the indirect symbol table. Stub *i* is
   `indirect_symbols[section.reserved1 + i]` (LC_DYSYMTAB), with 12-byte stubs, or 16 bytes
   for arm64e `__auth_stubs`. This works for both chained fixups and DYLD_INFO, so it avoids
   parsing chained fixups (goblin 0.8 doesn't).
2. Scan `__text` for `BL` to the stubs of `_CCCrypt`, `_CCCryptorCreate` and
   `_CCCryptorCreateWithMode`.
3. Walk back at most ~8 instructions in the same basic block for the last write to each
   argument register: `MOVZ`/`ORR wN, wzr, #imm`, or `MOV wN, wM` where wM is a known immediate.
   - `CCCrypt` and `CCCryptorCreate`: w1 = algorithm, w2 = options.
   - `CCCryptorCreateWithMode`: w1 = mode, w2 = algorithm.
4. Emit findings from the values:
   - algorithm DES=1 → CRYPTO-001, 3DES=2 → 002, RC4=4 → 003, RC2=5 → 004, Blowfish=6 → 006
   - options & kCCOptionECBMode (2), or mode kCCModeECB (1) → 005
   - Report only immediates. A register loaded from memory or a parameter is unknown, not a finding.
5. Keep the string rules for headers and source, and dedupe by rule ID. Swift passes the
   same immediates. Also check an optimised Release build where the call is inlined into a
   wrapper.

Tests: a hand-assembled Mach-O with one stub and one `MOVZ w1,#1; MOVZ w2,#2; BL stub`
sequence. Then close the six known_gaps in `pavise-testapps/expect/dvia-ng.yaml`.

## 2. Hash-based pinning: QS-API-023 (Fortress)

**Problem.** QS-API-023 only knows anchor-certificate pinning
(`SecTrustSetAnchorCertificates[Only]`) and TrustKit. SPKI pinning written by hand in the
`urlSession(_:didReceive:)` delegate imports none of these. It uses
`SecTrustEvaluateWithError` + `SecTrustCopyCertificateChain` (or
`SecTrustGetCertificateAtIndex`) + `SecCertificateCopyKey` +
`SecKeyCopyExternalRepresentation`, then hashes the key. QS-API-023 in the app's own
binaries also settles the NET-004 pinning check (`pinning_settled` in `src/lib.rs`), so a
miss can surface as a false QS-NET-004 when the string signal also misses.

**Fix: an `all_of` symbol group** on `ApiRule` (`src/binary/symbols.rs`):
- `all_of: [[_SecTrustEvaluateWithError, _SecCertificateCopyKey, _SecKeyCopyExternalRepresentation]]`.
  The rule fires if any `symbols` entry matches or every symbol of one group is imported.
  The evidence lists the group.
- Each symbol alone is ordinary TLS or key handling. Only the combination indicates pinning,
  so don't add them to `symbols`.
- Check on the corpus that apps like Bitwarden or Signal-style clients gain it and plain
  URLSession apps don't. Then close the known_gap in `pavise-testapps/expect/fortress.yaml`.

## Not pavise work

API-011/API-019 (real Substrate/Realm SDKs) and the SEC-010/SEC-021 Decoy traps (App Store
symbols upload, iOS Rust staticlib) need fixtures from `pavise-testapps` P2 (Polyglot).
Nothing needs to change in pavise.
