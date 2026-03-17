# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Pavise, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email your report to the maintainers with a description of the vulnerability, steps to reproduce, and any relevant context.
3. You should receive an acknowledgment within 48 hours.
4. A fix will be developed privately and released as a patch version.

## Scope

Pavise is a static analysis tool that processes untrusted input (IPA/APK files). Security-relevant areas include:

- **ZIP extraction**: Path traversal (ZIP slip), decompression bombs
- **Binary parsing**: Malformed Mach-O/ELF handling via goblin
- **Regex engine**: Catastrophic backtracking (ReDoS)
- **Network requests**: DNS/geolocation lookups (opt-in via `--network`)
- **Server mode**: File upload handling, concurrent scan limits

## Design Principles

- All archive extraction is performed in-memory; no files are written to disk during scanning.
- User-supplied regex patterns are never accepted; all patterns are loaded from bundled YAML rules.
- Network functionality is opt-in and disabled by default.
- `#![forbid(unsafe_code)]` is enforced in both the library and CLI binary.
