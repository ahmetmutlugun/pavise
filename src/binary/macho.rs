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
    // The compiler only emits a canary for functions with stack buffers, so a
    // missing import is not proof of a missing flag when there is no such code.
    let canary_na = if has_canary {
        None
    } else {
        canary_not_applicable(&imports, text_section_size(macho))
    };
    protections.push(BinaryProtection {
        name: "Stack Canary".to_string(),
        enabled: has_canary,
        severity: if has_canary {
            Severity::Secure
        } else if canary_na.is_some() {
            Severity::Info
        } else {
            Severity::High
        },
        description: if has_canary {
            "Stack canary protection is present (___stack_chk_fail imported).".to_string()
        } else if let Some(reason) = canary_na {
            format!(
                "___stack_chk_fail not imported, but {} — nothing for a canary to protect.",
                reason
            )
        } else {
            "Stack canary protection is absent. Stack buffer overflows may not be detected."
                .to_string()
        },
    });

    // Canary status reflects app hardening at the main-executable level. A
    // framework/dylib lacking the symbol is far lower signal and must NOT raise
    // a HIGH app-wide finding (it previously did, contradicting the main
    // binary's own SECURE protection). The main executable lacking the canary is
    // the genuine HIGH; framework gaps are reported separately and downgraded.
    if let (Some(reason), true) = (canary_na, is_executable) {
        findings.push(Finding {
            id: "QS-BIN-002".to_string(),
            title: "Stack Canary Not Applicable".to_string(),
            description: format!(
                "The binary '{}' does not import ___stack_chk_fail, but {}. The compiler only \
                inserts canaries into functions with stack buffers, so their absence here is expected.",
                path, reason
            ),
            severity: Severity::Info,
            category: "binary".to_string(),
            cwe: Some("CWE-121".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-9".to_string()),
            evidence: vec![format!("___stack_chk_fail absent in {} ({})", path, reason)],
            remediation: None,
        });
    } else if !has_canary && is_executable {
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
    } else if !has_canary && canary_na.is_none() {
        // Framework/dylib without a canary — separate, downgraded finding that
        // never collides with the main executable's SECURE QS-BIN-002.
        findings.push(Finding {
            id: "QS-BIN-008".to_string(),
            title: "Framework Binary Without Stack Canary".to_string(),
            description: format!(
                "The bundled framework binary '{}' was built without stack canaries \
                (___stack_chk_fail absent). The main app binary's protection is unaffected, \
                but overflow bugs in this dependency would go undetected.",
                path
            ),
            severity: Severity::Warning,
            category: "binary".to_string(),
            cwe: Some("CWE-121".to_string()),
            owasp_mobile: Some("M7".to_string()),
            owasp_masvs: Some("MSTG-CODE-9".to_string()),
            evidence: vec![format!("___stack_chk_fail absent in {}", path)],
            remediation: Some("Rebuild the dependency with -fstack-protector-all, or update to a version that ships with stack protection.".to_string()),
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
    //   1. ObjC ARC:   _objc_storeStrong / _objc_retainAutoreleasedReturnValue …
    //   2. Swift ARC:  swift_retain / swift_release (Swift's own ARC symbols)
    //   3. ObjC usage: _objc_msgSend indicates the binary uses ObjC runtime
    //
    // If a binary has ObjC runtime usage but no ARC symbols → real finding (MRC).
    // If a binary has no ObjC/Swift symbols at all → skip check (pure C/C++).

    // Clang also emits objc_retain/objc_release calls under MRC, so only
    // entry points that exist solely for ARC codegen count as evidence.
    const OBJC_ARC_MARKERS: &[&str] = &[
        "_objc_storeStrong",
        "_objc_retainAutoreleasedReturnValue",
        "_objc_claimAutoreleasedReturnValue",
        "_objc_unsafeClaimAutoreleasedReturnValue",
        "_objc_autoreleaseReturnValue",
        "_objc_retainAutoreleaseReturnValue",
    ];
    let has_objc_arc = imports
        .iter()
        .any(|s| OBJC_ARC_MARKERS.contains(&s.as_str()));
    let has_swift_arc = imports.iter().any(|s| {
        s.contains("swift_retain")
            || s.contains("swift_release")
            || s.contains("swift_unknownObjectRetain")
            || s.contains("swift_unknownObjectRelease")
    });
    let has_objc_runtime = imports.iter().any(|s| s.contains("_objc_msgSend"));
    // MRC code still calls objc_retain/objc_release directly, but so does a
    // tiny ARC stub (Telegram's `main` has 10 ObjC imports and no ARC-only
    // calls). Only judge binaries with enough ObjC code for ARC codegen to
    // have emitted its markers.
    const MIN_OBJC_IMPORTS: usize = 20;
    let has_manual_refcount = imports
        .iter()
        .any(|s| s == "_objc_retain" || s == "_objc_release" || s == "_objc_autorelease");
    let objc_import_count = imports
        .iter()
        .filter(|s| s.starts_with("_objc_") || s.starts_with("_OBJC_"))
        .count();

    let has_arc = has_objc_arc || has_swift_arc;
    let uses_objc_or_swift = has_arc
        || (has_objc_runtime && has_manual_refcount && objc_import_count >= MIN_OBJC_IMPORTS);

    if uses_objc_or_swift {
        let arc_label = if has_swift_arc {
            "ARC enabled via Swift runtime (swift_retain/release present)."
        } else {
            "ARC is enabled (ARC-only Objective-C runtime entry points present)."
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

        if !has_arc && is_executable {
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
                evidence: vec![format!("No ARC-only runtime calls (_objc_storeStrong, _objc_retainAutoreleasedReturnValue) despite _objc_msgSend in {}", path)],
                remediation: Some("Enable ARC in Xcode build settings: 'Objective-C Automatic Reference Counting' = YES.".to_string()),
            });
        } else if !has_arc {
            // Framework/dylib using the ObjC runtime without ARC — informational;
            // many legitimate dependencies predate or opt out of ARC.
            findings.push(Finding {
                id: "QS-BIN-009".to_string(),
                title: "Framework Binary Without ARC".to_string(),
                description: format!(
                    "The bundled framework binary '{}' uses the Objective-C runtime without ARC. \
                    The main app binary is unaffected; manual memory management in this dependency \
                    carries some use-after-free risk.",
                    path
                ),
                severity: Severity::Info,
                category: "binary".to_string(),
                cwe: Some("CWE-416".to_string()),
                owasp_mobile: Some("M7".to_string()),
                owasp_masvs: Some("MSTG-CODE-9".to_string()),
                evidence: vec![format!("No ARC-only runtime calls (_objc_storeStrong, _objc_retainAutoreleasedReturnValue) despite _objc_msgSend in {}", path)],
                remediation: Some("Prefer dependencies built with ARC enabled.".to_string()),
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

    // Embedded frameworks/dylibs frequently lack an individual LC_CODE_SIGNATURE
    // (they are covered by the app's outer signature), so a missing per-framework
    // signature is not a vulnerability. Only the main executable matters here.
    if !has_code_signature && is_executable {
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
        .filter(|r| !is_safe_rpath(r))
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
            format!(
                "Non-standard LC_RPATH entries found: {}",
                rpath_commands.join(", ")
            )
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

    // Only the main executable's strip state is reported. Bundled frameworks
    // commonly retain symbols and are lower signal; flagging each one inflates
    // the report. (See check_debug_symbols: detection is DWARF-based, not a
    // symbol-count heuristic, so a stripped binary with a dynamic symbol table
    // is no longer misreported as "not stripped".)
    if has_debug_symbols && is_executable {
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
            id: "QS-BIN-010".to_string(),
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

/// True for system Swift paths and bundle-relative paths that stay inside the
/// signed, read-only `.app`. Extensions sit at `App.app/PlugIns/X.appex/`, so
/// Xcode gives them `@executable_path/../../Frameworks`; two `..` levels reach
/// the app root and no further.
fn is_safe_rpath(rpath: &str) -> bool {
    if SAFE_RPATHS.contains(&rpath) {
        return true;
    }
    let Some(rel) = rpath
        .strip_prefix("@executable_path")
        .or_else(|| rpath.strip_prefix("@loader_path"))
    else {
        return false;
    };
    if !(rel.is_empty() || rel.starts_with('/')) {
        return false;
    }
    rel.split('/').filter(|seg| *seg == "..").count() <= 2
}

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

/// Main executables below this `__text` size are launcher stubs (Telegram,
/// Flutter) whose real code lives in an embedded framework.
const STUB_TEXT_SIZE: u64 = 64 * 1024;

/// libc calls that operate on caller-provided buffers. A Swift binary that
/// imports none of them has no C-style stack buffers for a canary to guard.
const BUFFER_FUNCS: &[&str] = &[
    "_memcpy",
    "_memmove",
    "_memset",
    "_strcpy",
    "_strncpy",
    "_strcat",
    "_strncat",
    "_sprintf",
    "_snprintf",
    "_vsprintf",
    "_vsnprintf",
    "_sscanf",
    "_gets",
    "_read",
    "_strlcpy",
    "_strlcat",
    "___memcpy_chk",
    "___memmove_chk",
    "___memset_chk",
    "___strcpy_chk",
    "___strncpy_chk",
    "___strcat_chk",
    "___sprintf_chk",
    "___snprintf_chk",
];

/// Why a missing stack canary is not a finding, or `None` if it is one.
fn canary_not_applicable(imports: &[String], text_size: u64) -> Option<&'static str> {
    if text_size < STUB_TEXT_SIZE {
        return Some("its __text section is a small launcher stub");
    }
    let is_swift = imports.iter().any(|s| s.starts_with("_swift_"));
    let uses_buffers = imports.iter().any(|s| BUFFER_FUNCS.contains(&s.as_str()));
    if is_swift && !uses_buffers {
        return Some("it is Swift code that imports no libc buffer functions");
    }
    None
}

fn text_section_size(macho: &MachO) -> u64 {
    for seg in &macho.segments {
        if seg.name().ok() != Some("__TEXT") {
            continue;
        }
        if let Ok(sections) = seg.sections() {
            for (sec, _) in sections {
                if sec.name().ok() == Some("__text") {
                    return sec.size;
                }
            }
        }
    }
    // No __text at all (e.g. bitcode-only): nothing to judge, treat as large.
    u64::MAX
}

/// Contents of the `__TEXT,<name>` section of the preferred slice (ARM64 in
/// a fat binary, else the first). Returns an empty vec for non-Mach-O data.
fn text_section(data: &[u8], name: &str) -> Vec<u8> {
    const ARM64_CPUTYPE: u32 = 0x0100_000c;
    let slice = match Mach::parse(data) {
        Ok(Mach::Binary(_)) => data,
        Ok(Mach::Fat(fat)) => {
            let Ok(arches) = fat.arches() else {
                return Vec::new();
            };
            let Some(arch) = arches
                .iter()
                .find(|a| a.cputype == ARM64_CPUTYPE)
                .or_else(|| arches.first())
            else {
                return Vec::new();
            };
            let start = arch.offset as usize;
            match data.get(start..start.saturating_add(arch.size as usize)) {
                Some(s) => s,
                None => return Vec::new(),
            }
        }
        Err(_) => return Vec::new(),
    };
    let Ok(macho) = MachO::parse(slice, 0) else {
        return Vec::new();
    };
    for seg in &macho.segments {
        if seg.name().ok() != Some("__TEXT") {
            continue;
        }
        if let Ok(sections) = seg.sections() {
            for (sec, sec_data) in sections {
                if sec.name().ok() == Some(name) {
                    return sec_data.to_vec();
                }
            }
        }
    }
    Vec::new()
}

/// String literals from `__TEXT,__ustring`. The compiler stores NSString
/// literals with non-ASCII characters there as NUL-terminated UTF-16LE, which
/// the byte-oriented printable-string scan cannot see.
pub fn ustrings(data: &[u8]) -> Vec<String> {
    let sec = text_section(data, "__ustring");
    let units: Vec<u16> = sec
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    units
        .split(|&u| u == 0)
        .filter(|s| s.len() >= 4)
        .map(|s| {
            char::decode_utf16(s.iter().copied())
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        })
        .collect()
}

/// Objective-C class names from `__TEXT,__objc_classname`. The runtime needs
/// them, so they survive symbol stripping — which makes them the signature
/// of SDKs linked statically into the main binary.
pub fn objc_class_names(data: &[u8]) -> Vec<String> {
    text_section(data, "__objc_classname")
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok().map(str::to_string))
        .collect()
}

fn check_debug_symbols(macho: &MachO) -> bool {
    // Debug info is indicated by a __DWARF segment (embedded dSYM) or __debug_*
    // sections. We deliberately do NOT infer "not stripped" from symbol-table
    // size: even a fully stripped Mach-O retains a dynamic symbol table
    // (imports/exports), so a symbol count threshold produced false positives
    // (pavise reporting "not stripped" where MobSF and `nm` agree it is).
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

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_bundle_rpaths_are_safe() {
        for r in [
            "/usr/lib/swift",
            "@executable_path/Frameworks",
            "@executable_path/../../Frameworks",
            "@loader_path/../../Frameworks",
            "@executable_path",
        ] {
            assert!(is_safe_rpath(r), "{r}");
        }
        for r in [
            "/tmp/libs",
            "@executable_path/../../../Documents",
            "@executable_pathX/Frameworks",
            "@rpath/Frameworks",
        ] {
            assert!(!is_safe_rpath(r), "{r}");
        }
    }

    /// arm64 MH_EXECUTE with a single `__TEXT,<sect>` section holding `payload`.
    fn macho_with_text_section(sect: &str, payload: &[u8]) -> Vec<u8> {
        fn name16(s: &str) -> [u8; 16] {
            let mut n = [0u8; 16];
            n[..s.len()].copy_from_slice(s.as_bytes());
            n
        }
        let (header_len, cmd_len) = (32u32, 72u32 + 80);
        let data_off = header_len + cmd_len;
        let total = data_off as u64 + payload.len() as u64;
        let mut b = Vec::new();
        for w in [
            0xFEED_FACFu32,
            0x0100_000C,
            0,
            2,
            1,
            cmd_len,
            0x0020_0000,
            0,
        ] {
            b.extend_from_slice(&w.to_le_bytes());
        }
        // LC_SEGMENT_64 __TEXT covering the whole file
        b.extend_from_slice(&0x19u32.to_le_bytes());
        b.extend_from_slice(&cmd_len.to_le_bytes());
        b.extend_from_slice(&name16("__TEXT"));
        for q in [0u64, total, 0, total] {
            b.extend_from_slice(&q.to_le_bytes());
        }
        for w in [5u32, 5, 1, 0] {
            b.extend_from_slice(&w.to_le_bytes());
        }
        // section_64
        b.extend_from_slice(&name16(sect));
        b.extend_from_slice(&name16("__TEXT"));
        b.extend_from_slice(&(data_off as u64).to_le_bytes());
        b.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        for w in [data_off, 0, 0, 0, 0, 0, 0, 0] {
            b.extend_from_slice(&w.to_le_bytes());
        }
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn ustrings_decode_utf16_literals() {
        let mut payload = Vec::new();
        for s in ["sk_live_ünïcode_42", "ab"] {
            for u in s.encode_utf16() {
                payload.extend_from_slice(&u.to_le_bytes());
            }
            payload.extend_from_slice(&[0, 0]);
        }
        let bin = macho_with_text_section("__ustring", &payload);
        assert_eq!(ustrings(&bin), vec!["sk_live_ünïcode_42"]);
        assert!(ustrings(b"not a mach-o").is_empty());
    }

    #[test]
    fn objc_class_names_read_from_classname_section() {
        let bin = macho_with_text_section("__objc_classname", b"FIRApp\0AppDelegate\0");
        assert_eq!(objc_class_names(&bin), vec!["FIRApp", "AppDelegate"]);
    }

    fn imports(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn canary_na_for_stub_main() {
        // Telegram: 520-byte __text, all code in TelegramUI.framework.
        assert!(canary_not_applicable(&imports(&["_swift_release", "_memcpy"]), 520).is_some());
    }

    #[test]
    fn canary_na_for_swift_without_buffers() {
        let i = imports(&["_swift_retain", "_objc_msgSend", "___chkstk_darwin"]);
        assert!(canary_not_applicable(&i, 10 << 20).is_some());
    }

    #[test]
    fn canary_required_for_large_c_binary() {
        // FunkiniOS: 26 MB of C/C++ calling memcpy/snprintf with no canary.
        let i = imports(&["_memcpy", "_snprintf", "_objc_msgSend"]);
        assert_eq!(canary_not_applicable(&i, 26 << 20), None);
    }

    #[test]
    fn canary_required_for_swift_using_buffers() {
        let i = imports(&["_swift_retain", "___memcpy_chk"]);
        assert_eq!(canary_not_applicable(&i, 10 << 20), None);
    }

    #[test]
    fn missing_text_section_is_not_a_stub() {
        assert_eq!(
            canary_not_applicable(&imports(&["_memcpy"]), u64::MAX),
            None
        );
    }
}
