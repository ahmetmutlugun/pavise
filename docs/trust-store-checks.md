# Bundled trust stores, pins and weak EC keys (QS-CERT-003…007)

Added 2026-10-26 after the eMudhra key compromise (Mozilla bug 2083449). Code:
`src/resources/x509.rs` (DER/PEM reading), `weak_ec.rs` (small-scalar search), `trust.rs`
(rules); data: `data/distrusted_cas.tsv`; tests: `tests/trust_store.rs`.

## Why apps are exposed when browsers are not

Apps using URLSession validate against Apple's trust store and get Apple's blocks and root
removals automatically. Apps that ship their own root list don't: curl/OpenSSL `cacert.pem`,
gRPC's `roots.pem`, mbedTLS/BearSSL stores compiled into a library. A PEM list can't express
revocation, and those stacks rarely check CRL/OCSP, so a CA distrusted everywhere else stays
trusted in the app. Cloudflare had to ship fixed WARP and 1.1.1.1 iOS builds for this incident.

## The eMudhra chain (verified 2026-10-26)

- Eight P-384 intermediates (EM DV/OV/EV TLS CA - G3B/G3C, EM OV CS CA - G3B/G3C) have
  private keys 4, 56, 66, 115, 155, 156, 230 and 237. `weak_ec` tests build each d·G and
  check that its SPKI hash is the one listed for that intermediate. Every listed certificate
  SHA-256 was checked against its crt.sh DER.
- Issued by **emSign Root TLS CA - G3** / **emSign Root CS CA - G3**, which are cross-signed by
  **emSign ECC Root CA - G3**. NSS removed that root (bug 2084101, rev 26d38a0c3fb8). curl's
  extract dropped it between 2026-09-25 and 2026-10-20, so every older `cacert.pem` has it.
- Each intermediate also has a **Sectigo cross-sign from AAA Certificate Services** (valid to
  2028-12-31, revoked). AAA isn't in Mozilla's TLS store but appears in older or OS-derived
  lists. A store trusting AAA without revocation checks accepts forged chains.

## Rules

| ID | Severity | Fires when |
|---|---|---|
| QS-CERT-003 | High | A bundled cert/key is a compromised eMudhra key or its issuer |
| QS-CERT-004 | High | An EC (P-256/P-384) key's private scalar is below 2^16 (BSGS, ~ms per key) |
| QS-CERT-005 | Warning | A store of ≥ 10 certs includes the cross-signer (AAA Certificate Services) |
| QS-CERT-006 | Warning | A bundled cert is a root Mozilla removed for distrust |
| QS-CERT-007 | Warning / Info | An SPKI pin (base64 or hex) names a compromised / distrusted key |

Keys are matched by **SPKI SHA-256**, so cross-signed and reissued copies match. Certificates
come from PEM blocks anywhere in any file (including `\r\n`-separated C strings in Mach-O
`__cstring` and `\n`-escaped JSON) and from `.der/.cer/.crt` files. Listed keys are also found
by their **raw bytes**: the EC coordinates, or the first 64 bytes of the RSA modulus. That
catches DER arrays, bare SPKIs and BearSSL trust anchors in any file except ZIP, image and
asset-catalog containers. A single Teddy (SIMD) pass covers those bytes and the pin strings,
which is about 15× faster than `AhoCorasick` on arm64. QS-CERT-005 needs a real root store
(≥ 10 PEM keys or DER v3 certificate headers): pinning AAA on its own is ordinary. Pins on AAA
are not flagged.

Distrusted roots listed: Certinomis - Root CA (1552374), Camerfirma Chambers of Commerce /
Global Chambersign Root - 2008 (1692094), E-Tugra Global Root CA RSA/ECC v3 (1842928),
TrustCor ECA-1 / RootCert CA-1 / CA-2 (1803453, 1851049). Roots removed only because they
expired or at the CA's own request (Certinomis - Autorité Racine, E-Tugra Certification
Authority, Camerfirma's 2003 roots) are not listed.

## Corpus result (33 apps)

Four apps fire. Apps aren't named while the vendors are told.
- An emulator whose networking library compiles 164 PEM roots, including AAA Certificate
  Services (QS-CERT-005) plus Certinomis and both Camerfirma 2008 roots (QS-CERT-006).
- Three apps ship a real-time communication framework with a built-in store of 147 DER roots.
  All three trust AAA (QS-CERT-005). One build still has emSign ECC Root CA - G3
  (QS-CERT-003, High), which drops that app from D 46 to F 23. Only the raw-bytes search
  finds these. They are outdated builds: WebRTC's upstream `rtc_base/ssl_roots.h` was
  regenerated on 2026-10-20 from pki.goog with none of the listed CAs. The exposed path is
  probably TURN-over-TLS only, since media runs over DTLS-SRTP. Framework hits stay High on
  purpose (decided 2026-10-26): the app ships the code, and static analysis can't tell
  whether that TLS path is reachable.
Bundled mbedTLS test certs trigger nothing, and the `corpus_grades` bands still pass. Scan
time rises about 6% on the 2.5 GB emulator and about 3% on the others.

## Adding an entry

1. Get the certificate DER from crt.sh or a curl `cacert-*.pem`, and check its SHA-256
   against the Mozilla bug.
2. SPKI hash: `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst
   -sha256 -binary | base64`.
3. Add a TSV row with a primary source URL and the base64 SPKI DER (`… -outform der | base64`).
   Loading checks the DER hashes to the row's SPKI hash, and `trust::tests` checks the source
   URL. More than 64 patterns falls back to the slower automaton.

## Gaps

- Raw-bytes hits only cover listed keys. Weak-key checks (QS-CERT-004) need a parsed PEM/DER
  key. A raw hit gives no certificate name beyond the listed one.
- Symantec's partial distrust and Entrust/Chunghwa "distrust after" dates aren't modelled.
  DigiNotar (expired 2025) isn't listed.
- No RSA weak-key checks (shared primes, ROCA).
- `--network` doesn't yet fetch the app's own server chains to flag eMudhra-issued backends.
