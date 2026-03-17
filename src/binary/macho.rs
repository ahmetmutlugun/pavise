use anyhow::{Context, Result};
use goblin::mach::{Mach, MachO};
use std::collections::HashSet;
use tracing::debug;

use crate::types::{BinaryInfo, BinaryProtection, Finding, Severity};

pub struct MachoAnalysisResult {
    pub binary_info: BinaryInfo,
    pub findings: Vec<Finding>,
    pub imports: Vec<String>,
}

pub fn analyze(data: &[u8], path: &str) -> Result<MachoAnalysisResult> {
    let mach = Mach::parse(data).with_context(|| format!("Failed to parse Mach-O: {}", path))?;

    match mach {
        Mach::Binary(macho) => analyze_single(&macho, data, path),
        Mach::Fat(fat) => {
            // For fat/universal binaries, prefer ARM64, fallback to first arch
            let arch_count = fat.narches;
            debug!("Fat binary with {} architectures", arch_count);

            let mut preferred: Option<MachoAnalysisResult> = None;
            for i in 0..arch_count {
                if let Ok(arch) = fat.get(i) {
                    // SingleArch is either a MachO or Archive
                    let macho_opt = match arch {
                        goblin::mach::SingleArch::MachO(m) => Some(m),
                        _ => None,
                    };
                    if let Some(m) = macho_opt {
                        if let Ok(result) = analyze_single(&m, data, path) {
                            let is_arm64 = result.binary_info.arch.contains("ARM64")
                                || result.binary_info.arch.contains("arm64");
                            if is_arm64 || preferred.is_none() {
                                preferred = Some(result);
                            }
                            if is_arm64 {
                                break;
                            }
                        }
                    }
                }
            }
            preferred.context("No valid architectures found in fat binary")
        }
    }
}

// Mach-O file type constants
const MH_EXECUTE: u32 = 0x2;

// Mach-O header flag constants
const MH_PIE_FLAG: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

fn analyze_single(macho: &MachO, raw_data: &[u8], path: &str) -> Result<MachoAnalysisResult> {
    let header = &macho.header;

    // Determine architecture
    let (arch, bits) = arch_from_header(header.cputype, header.cpusubtype);

    // Whether this binary is a main executable vs. a dylib/framework
    let is_executable = header.filetype == MH_EXECUTE;

    let mut protections: Vec<BinaryProtection> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    // --- NX (No-Execute) ---
    // MH_NO_HEAP_EXECUTION requests that the kernel map heap/stack as non-executable.
    // On ARM64 iOS devices NX is always enforced by hardware (XN bit) regardless of
    // this flag, so we report it as secure on ARM64.
    let has_nx_flag = (header.flags & MH_NO_HEAP_EXECUTION) != 0;
    let is_arm64 = arch.contains("ARM64") || arch.contains("arm64");
    let nx_enforced = has_nx_flag || is_arm64;
    protections.push(BinaryProtection {
        name: "NX (No-Execute)".to_string(),
        enabled: nx_enforced,
        severity: if nx_enforced { Severity::Secure } else { Severity::Info },
        description: if has_nx_flag {
            "MH_NO_HEAP_EXECUTION flag set — heap/stack marked non-executable.".to_string()
        } else if is_arm64 {
            "NX enforced by ARM64 hardware (XN bit). MH_NO_HEAP_EXECUTION flag absent but not required.".to_string()
        } else {
            "MH_NO_HEAP_EXECUTION flag absent. Heap/stack may be executable.".to_string()
        },
    });

    // --- PIE ---
    // MH_PIE only applies to MH_EXECUTE. Dylibs/frameworks are always position-independent
    // by design — flagging them for missing PIE is a false positive.
    if is_executable {
        let has_pie = (header.flags & MH_PIE_FLAG) != 0;
        protections.push(BinaryProtection {
            name: "Position Independent Executable (PIE)".to_string(),
            enabled: has_pie,
            severity: if has_pie {
                Severity::Secure
            } else {
                Severity::High
            },
            description: if has_pie {
                "Binary is compiled with PIE, enabling ASLR.".to_string()
            } else {
                "Binary is NOT compiled with PIE. ASLR cannot be applied.".to_string()
            },
        });

        if !has_pie {
            findings.push(Finding {
                id: "QS-BIN-001".to_string(),
                title: "PIE (ASLR) Disabled".to_string(),
                description: format!(
                    "The binary '{}' is not compiled with Position Independent Executable (PIE) flag. \
                    Without PIE, ASLR cannot randomize the base address, making it easier to exploit memory corruption vulnerabilities.",
                    path
                ),
                severity: Severity::High,
                category: "binary".to_string(),
                cwe: Some("CWE-119".to_string()),
                owasp_mobile: Some("M7".to_string()),
                owasp_masvs: Some("MSTG-CODE-9".to_string()),
                evidence: vec![format!("MH_PIE flag absent in {}", path)],
                remediation: Some("Compile with -fPIE and link with -pie (Xcode: 'Generate Position-Dependent Code' = NO).".to_string()),
            });
        } else {
            findings.push(Finding {
                id: "QS-BIN-001".to_string(),
                title: "PIE (ASLR) Enabled".to_string(),
                description: format!(
                    "The binary '{}' is compiled with PIE. ASLR is enabled and will randomize \
                    the base address on each launch.",
                    path
                ),
                severity: Severity::Secure,
                category: "binary".to_string(),
                cwe: Some("CWE-119".to_string()),
                owasp_mobile: Some("M7".to_string()),
                owasp_masvs: Some("MSTG-CODE-9".to_string()),
                evidence: vec![format!("MH_PIE flag set in {}", path)],
                remediation: None,
            });
        }
    }

    // --- Stack Canary ---
    let imports = collect_imports(macho);
    let has_canary = imports
        .iter()
        .any(|s| s.contains("___stack_chk_fail") || s.contains("___stack_chk_guard"));
    protections.push(BinaryProtection {
        name: "Stack Canary".to_string(),
        enabled: has_canary,
        severity: if has_canary {
            Severity::Secure
        } else {
            Severity::High
        },
        description: if has_canary {
            "Stack canary protection is present (___stack_chk_fail imported).".to_string()
        } else {
            "Stack canary protection is absent. Stack buffer overflows may not be detected."
                .to_string()
        },
    });

    if !has_canary {
        findings.push(Finding {
            id: "QS-BIN-002".to_string(),
            title: "Stack Canary Not Found".to_string(),
            description: format!(
                "The binary '{}' does not appear to use stack canaries (___stack_chk_fail not found in imports). \
                Stack buffer overflows may not be detected at runtime.",
                path
            ),
            severity: Severity::High,
            category: "binary".to_string(),
            cwe: Some("CWE-121".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-9".to_string()),
            evidence: vec![format!("___stack_chk_fail absent in {}", path)],
            remediation: Some("Compile with stack protection enabled: -fstack-protector-all (Xcode default for release builds).".to_string()),
        });
    } else if is_executable {
        findings.push(Finding {
            id: "QS-BIN-002".to_string(),
            title: "Stack Canary Protection Present".to_string(),
            description: format!(
                "The binary '{}' uses stack canaries (___stack_chk_fail present). Stack buffer \
                overflows will be detected and the process will abort.",
                path
            ),
            severity: Severity::Secure,
            category: "binary".to_string(),
            cwe: Some("CWE-121".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-9".to_string()),
            evidence: vec![format!("___stack_chk_fail present in {}", path)],
            remediation: None,
        });
    }

    // --- ARC ---
    // ARC only applies to binaries that use Objective-C or Swift.
    // Pure C/C++ libraries (like gRPC, OpenSSL, abseil) don't use ObjC/Swift at all —
    // flagging them for missing ARC is a false positive.
    //
    // Detection strategy:
    //   1. ObjC ARC:   _objc_release / _objc_retain / _objc_storeStrong
    //   2. Swift ARC:  swift_retain / swift_release (Swift's own ARC symbols)
    //   3. ObjC usage: _objc_msgSend indicates the binary uses ObjC runtime
    //
    // If a binary has ObjC runtime usage but no ARC symbols → real finding (MRC).
    // If a binary has no ObjC/Swift symbols at all → skip check (pure C/C++).

    let has_objc_arc = imports.iter().any(|s| {
        s.contains("_objc_release")
            || s.contains("_objc_retain")
            || s.contains("_objc_storeStrong")
            || s.contains("_objc_autorelease")
    });
    let has_swift_arc = imports.iter().any(|s| {
        s.contains("swift_retain")
            || s.contains("swift_release")
            || s.contains("swift_unknownObjectRetain")
            || s.contains("swift_unknownObjectRelease")
    });
    let has_objc_runtime = imports.iter().any(|s| s.contains("_objc_msgSend"));

    let has_arc = has_objc_arc || has_swift_arc;
    let uses_objc_or_swift = has_arc || has_objc_runtime;

    if uses_objc_or_swift {
        let arc_label = if has_swift_arc {
            "ARC enabled via Swift runtime (swift_retain/release present)."
        } else {
            "ARC is enabled (Objective-C retain/release functions present)."
        };
        protections.push(BinaryProtection {
            name: "Automatic Reference Counting (ARC)".to_string(),
            enabled: has_arc,
            severity: if has_arc { Severity::Secure } else { Severity::High },
            description: if has_arc {
                arc_label.to_string()
            } else {
                "ARC is not detected despite ObjC runtime usage. Manual memory management increases risk of use-after-free bugs.".to_string()
            },
        });

        if !has_arc {
            findings.push(Finding {
                id: "QS-BIN-003".to_string(),
                title: "ARC (Automatic Reference Counting) Not Detected".to_string(),
                description: format!(
                    "The binary '{}' uses the Objective-C runtime but does not appear to use ARC. \
                    Manual memory management is error-prone and increases the risk of use-after-free and double-free vulnerabilities.",
                    path
                ),
                severity: Severity::High,
                category: "binary".to_string(),
                cwe: Some("CWE-416".to_string()),
                owasp_mobile: Some("M7".to_string()),
                owasp_masvs: Some("MSTG-CODE-9".to_string()),
                evidence: vec![format!("_objc_release/_objc_retain absent despite _objc_msgSend in {}", path)],
                remediation: Some("Enable ARC in Xcode build settings: 'Objective-C Automatic Reference Counting' = YES.".to_string()),
            });
        } else if is_executable {
            findings.push(Finding {
                id: "QS-BIN-003".to_string(),
                title: "ARC (Automatic Reference Counting) Enabled".to_string(),
                description: format!(
                    "The binary '{}' uses ARC for memory management. Retain/release calls are \
                    compiler-managed, reducing the risk of use-after-free and double-free bugs.",
                    path
                ),
                severity: Severity::Secure,
                category: "binary".to_string(),
                cwe: Some("CWE-416".to_string()),
                owasp_mobile: Some("M7".to_string()),
                owasp_masvs: Some("MSTG-CODE-9".to_string()),
                evidence: vec![format!("ARC symbols present in {}", path)],
                remediation: None,
            });
        }
    }

    // --- Code Signature ---
    let has_code_signature = macho.load_commands.iter().any(|lc| {
        matches!(
            lc.command,
            goblin::mach::load_command::CommandVariant::CodeSignature(_)
        )
    });
    protections.push(BinaryProtection {
        name: "Code Signature".to_string(),
        enabled: has_code_signature,
        severity: if has_code_signature {
            Severity::Secure
        } else {
            Severity::High
        },
        description: if has_code_signature {
            "Binary has a code signature (LC_CODE_SIGNATURE present).".to_string()
        } else {
            "Binary lacks a code signature. This may indicate tampering or a development build."
                .to_string()
        },
    });

    if !has_code_signature {
        findings.push(Finding {
            id: "QS-BIN-004".to_string(),
            title: "Code Signature Missing".to_string(),
            description: format!(
                "The binary '{}' does not contain an LC_CODE_SIGNATURE load command. iOS requires valid code signatures for all production apps.",
                path
            ),
            severity: Severity::High,
            category: "binary".to_string(),
            cwe: Some("CWE-494".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-1".to_string()),
            evidence: vec![format!("LC_CODE_SIGNATURE absent in {}", path)],
            remediation: Some("Sign the binary with a valid Apple developer certificate using codesign.".to_string()),
        });
    } else if is_executable {
        findings.push(Finding {
            id: "QS-BIN-004".to_string(),
            title: "Code Signature Present".to_string(),
            description: format!(
                "The binary '{}' contains an LC_CODE_SIGNATURE load command. The binary is \
                signed and iOS will verify its integrity before launch.",
                path
            ),
            severity: Severity::Secure,
            category: "binary".to_string(),
            cwe: Some("CWE-494".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-1".to_string()),
            evidence: vec![format!("LC_CODE_SIGNATURE present in {}", path)],
            remediation: None,
        });
    }

    // --- Encryption ---
    let (has_encryption, is_encrypted) = check_encryption(macho);
    protections.push(BinaryProtection {
        name: "Binary Encryption".to_string(),
        enabled: is_encrypted,
        severity: if is_encrypted {
            Severity::Secure
        } else {
            Severity::Warning
        },
        description: if is_encrypted {
            "Binary encryption is active (cryptid != 0).".to_string()
        } else if has_encryption {
            "Encryption load command present but cryptid = 0 (not encrypted / decrypted)."
                .to_string()
        } else {
            "No encryption load command found.".to_string()
        },
    });

    // QS-BIN-005: FairPlay encryption only applies to MH_EXECUTE (the main app binary).
    // Bundled frameworks (MH_DYLIB) are never individually encrypted — the App Store
    // encrypts only the top-level executable. Flagging dylibs here is a false positive.
    if has_encryption && !is_encrypted && is_executable {
        findings.push(Finding {
            id: "QS-BIN-005".to_string(),
            title: "Binary Not Encrypted (cryptid = 0)".to_string(),
            description: format!(
                "The binary '{}' has an LC_ENCRYPTION_INFO load command with cryptid = 0, indicating the binary is not encrypted. This may be a development or decrypted build.",
                path
            ),
            severity: Severity::Warning,
            category: "binary".to_string(),
            cwe: Some("CWE-311".to_string()),
            owasp_mobile: Some("M9".to_string()),
            owasp_masvs: Some("MSTG-CODE-1".to_string()),
            evidence: vec![format!("LC_ENCRYPTION_INFO.cryptid = 0 in {}", path)],
            remediation: Some("Distribute through the App Store; the Store applies FairPlay encryption automatically.".to_string()),
        });
    }

    // --- RPATH ---
    // Only flag RPATHs that are not in the known-safe whitelist. Xcode always
    // emits /usr/lib/swift and @executable_path/Frameworks — flagging those
    // would be a false positive on every Swift app.
    let all_rpaths: Vec<String> = collect_rpaths(macho, raw_data);
    let rpath_commands: Vec<String> = all_rpaths
        .iter()
        .filter(|r| !SAFE_RPATHS.iter().any(|safe| r.as_str() == *safe))
        .cloned()
        .collect();
    let has_dangerous_rpath = !rpath_commands.is_empty();
    let has_any_rpath = !all_rpaths.is_empty();
    protections.push(BinaryProtection {
        name: "RPATH".to_string(),
        enabled: !has_dangerous_rpath,
        severity: if has_dangerous_rpath {
            Severity::Warning
        } else {
            Severity::Secure
        },
        description: if has_dangerous_rpath {
            format!("Non-standard LC_RPATH entries found: {}", rpath_commands.join(", "))
        } else if has_any_rpath {
            "All LC_RPATH entries are standard Xcode paths (safe).".to_string()
        } else {
            "No LC_RPATH entries (N/A).".to_string()
        },
    });

    if has_dangerous_rpath {
        findings.push(Finding {
            id: "QS-BIN-006".to_string(),
            title: "RPATH Set in Binary".to_string(),
            description: format!(
                "The binary '{}' contains LC_RPATH load commands. @rpath dylib loading can be abused for dylib hijacking if the path includes user-writable directories.",
                path
            ),
            severity: Severity::Warning,
            category: "binary".to_string(),
            cwe: Some("CWE-427".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-PLATFORM-9".to_string()),
            evidence: rpath_commands.clone(),
            remediation: Some("Review RPATH entries. Ensure none point to user-writable directories.".to_string()),
        });
    }

    // --- Debug Symbols ---
    let has_debug_symbols = check_debug_symbols(macho);
    protections.push(BinaryProtection {
        name: "Symbols Stripped".to_string(),
        enabled: !has_debug_symbols,
        severity: if has_debug_symbols { Severity::Warning } else { Severity::Secure },
        description: if has_debug_symbols {
            "Debug symbols or DWARF sections detected. Symbol stripping is recommended for release builds.".to_string()
        } else {
            "Binary appears to have symbols stripped.".to_string()
        },
    });

    if has_debug_symbols {
        findings.push(Finding {
            id: "QS-BIN-007".to_string(),
            title: "Debug Symbols Not Stripped".to_string(),
            description: format!(
                "The binary '{}' contains debug symbols or DWARF sections. This makes reverse engineering significantly easier.",
                path
            ),
            severity: Severity::Warning,
            category: "binary".to_string(),
            cwe: Some("CWE-215".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-3".to_string()),
            evidence: vec![format!("Debug sections present in {}", path)],
            remediation: Some("Strip symbols in release builds: Xcode 'Strip Debug Symbols During Copy' = YES, 'Deployment Postprocessing' = YES.".to_string()),
        });
    }

    // --- DWARF Source Path Leaks ---
    let dwarf_paths = extract_dwarf_source_paths(macho);
    if !dwarf_paths.is_empty() {
        findings.push(Finding {
            id: "QS-BIN-008".to_string(),
            title: "Source File Paths Leaked in DWARF Debug Info".to_string(),
            description: format!(
                "The binary '{}' contains absolute build-machine paths in its DWARF debug sections. \
                These paths reveal developer usernames, CI system layout, and project directory structure, \
                aiding attackers in targeted reverse engineering.",
                path
            ),
            severity: Severity::Warning,
            category: "binary".to_string(),
            cwe: Some("CWE-215".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-3".to_string()),
            evidence: dwarf_paths.iter().take(5).cloned().collect(),
            remediation: Some("Set 'Strip Debug Symbols During Copy = YES' in Xcode release build settings.".to_string()),
        });
    }

    let binary_info = BinaryInfo {
        path: path.to_string(),
        arch,
        bits,
        protections,
    };

    Ok(MachoAnalysisResult {
        binary_info,
        findings,
        imports,
    })
}

fn arch_from_header(cputype: u32, cpusubtype: u32) -> (String, u8) {
    match cputype {
        12 => {
            // CPU_TYPE_ARM
            match cpusubtype & 0xFF {
                0 => ("ARM".to_string(), 32),
                _ => ("ARM".to_string(), 32),
            }
        }
        // CPU_TYPE_ARM64 = 0x0100000c = 16777228
        16777228 => ("ARM64".to_string(), 64),
        // CPU_TYPE_X86_64 = 0x01000007
        16777223 => ("x86_64".to_string(), 64),
        7 => ("x86".to_string(), 32),
        _ => (format!("Unknown({})", cputype), 64),
    }
}

fn collect_imports(macho: &MachO) -> Vec<String> {
    let mut imports: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Source 1: dyld bind info (works for binaries with DYLD_INFO/DYLD_INFO_ONLY load command)
    if let Ok(import_list) = macho.imports() {
        for imp in import_list {
            let name = imp.name.to_string();
            if seen.insert(name.clone()) {
                imports.push(name);
            }
        }
    }

    // Source 2: LC_SYMTAB undefined external symbols.
    //
    // Newer ARM64 binaries use "chained fixups" (LC_DYLD_CHAINED_FIXUPS) instead of
    // DYLD_INFO, which goblin's `imports()` does not fully parse. Scanning the symbol
    // table (LC_SYMTAB) for undefined external symbols (N_EXT | N_UNDF) catches these.
    //
    // N_TYPE mask = 0x0e; N_UNDF = 0x00 (undefined); N_EXT = 0x01 (external/imported)
    if let Some(syms) = &macho.symbols {
        for (name, nlist) in syms.iter().flatten() {
            let is_undefined = (nlist.n_type & 0x0e) == 0x00;
            let is_external = (nlist.n_type & 0x01) != 0;
            if is_undefined && is_external && !name.is_empty() {
                let owned = name.to_string();
                if seen.insert(owned.clone()) {
                    imports.push(owned);
                }
            }
        }
    }

    imports
}

/// RPATHs that are always safe and should not trigger QS-BIN-006.
///
/// These are either read-only system locations or standard bundle-relative paths
/// that cannot be hijacked by an unprivileged user on a non-jailbroken device.
const SAFE_RPATHS: &[&str] = &[
    "/usr/lib/swift", // Standard Swift runtime — set by Xcode automatically
    "/usr/lib/swift-5.0",
    "@executable_path/Frameworks", // App bundle — not user-writable
    "@executable_path/../Frameworks",
    "@loader_path/Frameworks",
    "@loader_path/../Frameworks",
];

fn collect_rpaths(macho: &MachO, raw_data: &[u8]) -> Vec<String> {
    let mut rpaths = Vec::new();
    for lc in &macho.load_commands {
        if let goblin::mach::load_command::CommandVariant::Rpath(rpath) = &lc.command {
            // The path field is a byte offset from the start of the load command struct.
            // We reconstruct the string from the raw binary data at that offset.
            let lc_start = lc.offset;
            let str_offset = lc_start + rpath.path as usize;
            if let Some(bytes) = raw_data.get(str_offset..) {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                if let Ok(s) = std::str::from_utf8(&bytes[..end]) {
                    if !s.is_empty() {
                        rpaths.push(s.to_string());
                    }
                }
            }
        }
    }
    rpaths
}

fn check_encryption(macho: &MachO) -> (bool, bool) {
    for lc in &macho.load_commands {
        match &lc.command {
            goblin::mach::load_command::CommandVariant::EncryptionInfo32(info) => {
                return (true, info.cryptid != 0);
            }
            goblin::mach::load_command::CommandVariant::EncryptionInfo64(info) => {
                return (true, info.cryptid != 0);
            }
            _ => {}
        }
    }
    (false, false)
}

const BUILD_PATH_PREFIXES: &[&str] = &[
    "/Users/",
    "/home/",
    "/var/folders/",
    "/private/var/",
    "/build/",
    "/jenkins/",
    "/drone/",
    "/github/workspace/",
    "/runner/",
];

fn extract_path_strings(data: &[u8], out: &mut Vec<String>) {
    for s in data.split(|&b| b == 0) {
        if s.len() < 10 {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(s) {
            if BUILD_PATH_PREFIXES.iter().any(|p| text.starts_with(p)) {
                out.push(text.to_string());
            }
        }
    }
}

fn extract_dwarf_source_paths(macho: &MachO) -> Vec<String> {
    let mut paths = Vec::new();
    for seg in &macho.segments {
        if seg.name().ok() != Some("__DWARF") {
            continue;
        }
        if let Ok(sections) = seg.sections() {
            for (sec, sec_data) in sections {
                let name = sec.name().unwrap_or("");
                if name == "__debug_str" || name == "__debug_line_str" {
                    extract_path_strings(sec_data, &mut paths);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn check_debug_symbols(macho: &MachO) -> bool {
    // Check for __DWARF segment (present when dSYM is embedded in the binary)
    // and __debug_* sections (DWARF debug info in individual sections).
    for seg in &macho.segments {
        if seg.name().ok() == Some("__DWARF") {
            return true;
        }
        if let Ok(sections) = seg.sections() {
            for (sec, _) in sections {
                let name = sec.name().unwrap_or("");
                if name.starts_with("__debug_") {
                    return true;
                }
            }
        }
    }

    // Check for non-empty symtab
    if let Some(syms) = &macho.symbols {
        let count = syms.iter().count();
        if count > 5 {
            // More than a few symbols = not fully stripped
            return true;
        }
    }

    false
}
