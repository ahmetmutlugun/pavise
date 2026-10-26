//! Who calls an imported function: arm64 call-site attribution through the
//! debug map.
//!
//! An unstripped build keeps N_OSO/N_FUN stabs naming the object file each
//! function came from (`…/gRPC-Core.build/…/x.o`, `libFoo.a(x.o)`). Calls to an
//! import go through its `__stubs` entry, so every `BL`/`B` into that stub is a
//! call site, and the function containing it names the module (app target,
//! pod, SPM target) that makes the call. That separates "your code calls
//! strcpy" from "a statically linked dependency does".

use std::collections::{BTreeMap, HashMap};

use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};

const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const S_SYMBOL_STUBS: u32 = 0x8;
const SECTION_TYPE: u32 = 0xff;
const N_STAB: u8 = 0xe0;
const N_FUN: u8 = 0x24;
const N_SO: u8 = 0x64;
const N_OSO: u8 = 0x66;

/// Call-site counts per imported symbol, grouped by calling module.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Callers {
    /// Module containing `_main`: the app target's own code.
    pub app_module: Option<String>,
    /// Import name (`_strcpy`) → calling module → call sites.
    pub by_symbol: HashMap<String, BTreeMap<String, usize>>,
}

/// Callers of `symbols` in an arm64 (or fat with arm64) Mach-O, or `None` when
/// the binary has no debug map to attribute calls with.
pub fn callers(data: &[u8], symbols: &[&str]) -> Option<Callers> {
    match Mach::parse(data).ok()? {
        Mach::Binary(m) => callers_in(&m, data, symbols),
        Mach::Fat(fat) => {
            let arch = fat
                .arches()
                .ok()?
                .into_iter()
                .find(|a| a.cputype == CPU_TYPE_ARM64)?;
            let start = arch.offset as usize;
            let slice = data.get(start..start.checked_add(arch.size as usize)?)?;
            callers_in(&MachO::parse(slice, 0).ok()?, slice, symbols)
        }
    }
}

fn callers_in(macho: &MachO, data: &[u8], wanted: &[&str]) -> Option<Callers> {
    if macho.header.cputype != CPU_TYPE_ARM64 || wanted.is_empty() {
        return None;
    }
    let functions = debug_map_functions(macho);
    if functions.is_empty() {
        return None;
    }
    let stubs = stub_targets(macho, data, wanted);
    let text = macho
        .segments
        .iter()
        .filter_map(|seg| seg.sections().ok())
        .flatten()
        .find(|(s, _)| s.segname().ok() == Some("__TEXT") && s.name().ok() == Some("__text"));

    let mut out = Callers {
        app_module: main_module(macho, &functions),
        ..Default::default()
    };
    let Some((text, bytes)) = text else {
        return Some(out);
    };
    if stubs.is_empty() {
        return Some(out);
    }
    for (i, word) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let ins = u32::from_le_bytes(*word);
        // BL (0x94…) and B (0x14…, tail calls) with a signed 26-bit word offset.
        if ins & 0x7c00_0000 != 0x1400_0000 {
            continue;
        }
        let pc = text.addr + 4 * i as u64;
        let offset = (((ins & 0x03ff_ffff) << 6) as i32 >> 6) as i64 * 4;
        let target = pc.wrapping_add(offset as u64);
        let Some(name) = stubs.get(&target) else {
            continue;
        };
        let Some(module) = function_at(&functions, pc) else {
            continue;
        };
        *out.by_symbol
            .entry(name.clone())
            .or_default()
            .entry(module.to_string())
            .or_default() += 1;
    }
    Some(out)
}

/// A function's address range and the module of the object file it came from.
struct Function {
    start: u64,
    end: u64,
    module: String,
}

/// Function ranges from the debug map: each N_OSO names an object file, and
/// the N_FUN pairs that follow give (start address, size) of its functions.
fn debug_map_functions(macho: &MachO) -> Vec<Function> {
    let Some(symbols) = macho.symbols.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut module: Option<String> = None;
    let mut start: Option<u64> = None;
    for (name, nlist) in symbols.iter().flatten() {
        if nlist.n_type & N_STAB == 0 {
            continue;
        }
        match nlist.n_type {
            N_OSO => module = module_of_object(name),
            N_SO if name.is_empty() => module = None,
            N_FUN if !name.is_empty() => start = Some(nlist.n_value),
            N_FUN => {
                if let (Some(s), Some(m)) = (start.take(), &module) {
                    out.push(Function {
                        start: s,
                        end: s.saturating_add(nlist.n_value),
                        module: m.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    out.sort_by_key(|f| f.start);
    out
}

fn function_at(functions: &[Function], addr: u64) -> Option<&str> {
    let i = functions
        .partition_point(|f| f.start <= addr)
        .checked_sub(1)?;
    let f = &functions[i];
    (addr < f.end).then_some(f.module.as_str())
}

/// The module defining `_main`, i.e. the app target.
fn main_module(macho: &MachO, functions: &[Function]) -> Option<String> {
    let symbols = macho.symbols.as_ref()?;
    let addr = symbols
        .iter()
        .flatten()
        .find(|(name, n)| *name == "_main" && n.n_type & N_STAB == 0 && n.n_value != 0)?
        .1
        .n_value;
    function_at(functions, addr).map(str::to_string)
}

/// Stub address → import name, for the wanted imports. Stub *i* of a
/// `S_SYMBOL_STUBS` section is `indirect_symbols[reserved1 + i]`, each
/// `reserved2` bytes long.
fn stub_targets(macho: &MachO, data: &[u8], wanted: &[&str]) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let Some(symbols) = macho.symbols.as_ref() else {
        return out;
    };
    let Some((indirect_off, indirect_count)) =
        macho.load_commands.iter().find_map(|lc| match &lc.command {
            CommandVariant::Dysymtab(d) => Some((d.indirectsymoff as usize, d.nindirectsyms)),
            _ => None,
        })
    else {
        return out;
    };
    let indirect = |i: u32| -> Option<u32> {
        if i >= indirect_count {
            return None;
        }
        let at = indirect_off.checked_add(4 * i as usize)?;
        let b = data.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    for stub in stub_sections(macho, data) {
        // Section size and stub size come from the (untrusted) header; only
        // stubs with an indirect-table entry can name a symbol.
        let entries = indirect_count.saturating_sub(stub.first_indirect) as u64;
        for i in 0..(stub.size / stub.stub_size).min(entries) {
            // INDIRECT_SYMBOL_LOCAL / _ABS have the high bits set.
            let Some(sym) = indirect(stub.first_indirect + i as u32).filter(|s| s >> 30 == 0)
            else {
                continue;
            };
            if let Ok((name, _)) = symbols.get(sym as usize) {
                if wanted.contains(&name) {
                    let addr = stub.addr.wrapping_add(i.wrapping_mul(stub.stub_size));
                    out.insert(addr, name.to_string());
                }
            }
        }
    }
    out
}

struct StubSection {
    addr: u64,
    size: u64,
    first_indirect: u32,
    stub_size: u64,
}

/// `S_SYMBOL_STUBS` sections, read from the raw `section_64` headers: goblin's
/// `Section` drops `reserved1` (first indirect-symbol index) and `reserved2`
/// (stub size).
fn stub_sections(macho: &MachO, data: &[u8]) -> Vec<StubSection> {
    const SEGMENT_64_SIZE: usize = 72;
    const SECTION_64_SIZE: usize = 80;
    let u32_at = |at: usize| -> Option<u32> {
        let b = data.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at =
        |at: usize| -> Option<u64> { Some(u32_at(at)? as u64 | (u32_at(at + 4)? as u64) << 32) };
    let mut out = Vec::new();
    for lc in &macho.load_commands {
        let CommandVariant::Segment64(seg) = &lc.command else {
            continue;
        };
        for i in 0..seg.nsects as usize {
            let at = lc.offset + SEGMENT_64_SIZE + i * SECTION_64_SIZE;
            let (Some(addr), Some(size), Some(flags), Some(first), Some(stub_size)) = (
                u64_at(at + 32),
                u64_at(at + 40),
                u32_at(at + 64),
                u32_at(at + 68),
                u32_at(at + 72),
            ) else {
                break;
            };
            if flags & SECTION_TYPE == S_SYMBOL_STUBS && stub_size != 0 {
                out.push(StubSection {
                    addr,
                    size,
                    first_indirect: first,
                    stub_size: stub_size as u64,
                });
            }
        }
    }
    out
}

/// Module an object file belongs to, from its debug-map path:
/// - `…/libPods-App-gRPC-Core.a(x.o)` → `gRPC-Core`; `…/libFoo.a(x.o)` → `Foo`
/// - `…/<Target>.build/Objects-normal/arm64/x.o` (Xcode) or
///   `…/<Target>.build/x.o` (SwiftPM) → `<Target>`
/// - `…/Products/Release-iphoneos/FirebaseCore.o` (prelinked SPM target) → `FirebaseCore`
pub fn module_of_object(path: &str) -> Option<String> {
    if let Some(archive) = path.strip_suffix(')').and_then(|p| p.rsplit_once('(')) {
        let file = archive.0.rsplit('/').next()?;
        let lib = file.strip_suffix(".a").unwrap_or(file);
        let lib = lib.strip_prefix("lib").unwrap_or(lib);
        // CocoaPods without frameworks: `Pods-<AppTarget>-<Pod>`.
        let lib = match lib.strip_prefix("Pods-").and_then(|r| r.split_once('-')) {
            Some((_, pod)) => pod,
            None => lib,
        };
        return (!lib.is_empty()).then(|| lib.to_string());
    }
    let mut segments = path.rsplit('/');
    let file = segments.next()?;
    if let Some(target) = segments.find_map(|s| s.strip_suffix(".build")) {
        return Some(target.to_string());
    }
    file.strip_suffix(".o")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Synthetic binaries shared with `symbols` tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// arm64 executable: `_main` (App.build) calls strcpy; `_dep` (from
    /// libPods-App-Dep.a) calls strcpy and tail-calls rand. Section addresses
    /// equal file offsets.
    pub fn macho_with_calls() -> Vec<u8> {
        fn name16(s: &str) -> [u8; 16] {
            let mut n = [0u8; 16];
            n[..s.len()].copy_from_slice(s.as_bytes());
            n
        }
        let words = |b: &mut Vec<u8>, ws: &[u32]| ws.iter().for_each(|w| b.extend(w.to_le_bytes()));
        let (seg_len, symtab_len, dysymtab_len) = (72 + 2 * 80, 24u32, 80u32);
        let cmds_len = seg_len + symtab_len + dysymtab_len;
        let text_off = 32 + cmds_len;
        let stubs_off = text_off + 32;
        let sym_off = stubs_off + 24;

        let bl = |op: u32, pc: u32, target: u32| op | ((target.wrapping_sub(pc) / 4) & 0x03ff_ffff);
        let nop = 0xd503_201f;
        let (strcpy_stub, rand_stub) = (stubs_off, stubs_off + 12);
        let text = [
            bl(0x9400_0000, text_off, strcpy_stub),
            nop,
            nop,
            nop,
            bl(0x9400_0000, text_off + 16, strcpy_stub),
            bl(0x1400_0000, text_off + 20, rand_stub),
            nop,
            nop,
        ];

        let obj_app = "/b/Intermediates.noindex/App.build/Release-iphoneos/App.build/Objects-normal/arm64/main.o";
        let obj_dep = "/b/Build/libPods-App-Dep.a(x.o)";
        // (name, n_type, n_value)
        let syms: Vec<(&str, u8, u64)> = vec![
            ("/src/", N_SO, 0),
            ("main.m", N_SO, 0),
            (obj_app, N_OSO, 0),
            ("_main", N_FUN, text_off as u64),
            ("", N_FUN, 16),
            ("", N_SO, 0),
            ("/src/", N_SO, 0),
            ("x.c", N_SO, 0),
            (obj_dep, N_OSO, 0),
            ("_dep", N_FUN, text_off as u64 + 16),
            ("", N_FUN, 16),
            ("", N_SO, 0),
            ("_main", 0x0f, text_off as u64), // N_SECT | N_EXT
            ("_rand", 0x01, 0),               // undefined external
            ("_strcpy", 0x01, 0),
        ];
        let indirect_off = sym_off + 16 * syms.len() as u32;
        let str_off = indirect_off + 8;
        let mut strtab = vec![0u8];
        let mut nlists = Vec::new();
        for (name, n_type, value) in &syms {
            let idx = if name.is_empty() {
                0
            } else {
                strtab.len() as u32
            };
            if !name.is_empty() {
                strtab.extend(name.as_bytes());
                strtab.push(0);
            }
            nlists.extend(idx.to_le_bytes());
            nlists.extend([*n_type, 1, 0, 0]);
            nlists.extend(value.to_le_bytes());
        }
        let file_len = str_off + strtab.len() as u32;

        let mut b = Vec::new();
        words(
            &mut b,
            &[
                0xfeed_facf,
                CPU_TYPE_ARM64,
                0,
                2,
                3,
                cmds_len,
                0x0020_0000,
                0,
            ],
        );
        // LC_SEGMENT_64 __TEXT with __text and __stubs.
        words(&mut b, &[0x19, seg_len]);
        b.extend(name16("__TEXT"));
        b.extend(0u64.to_le_bytes());
        b.extend((file_len as u64).to_le_bytes());
        b.extend(0u64.to_le_bytes());
        b.extend((file_len as u64).to_le_bytes());
        words(&mut b, &[5, 5, 2, 0]);
        for (name, off, size, flags, reserved1, reserved2) in [
            ("__text", text_off, 32u32, 0x8000_0400u32, 0u32, 0u32),
            ("__stubs", stubs_off, 24, 0x8000_0408, 0, 12),
        ] {
            b.extend(name16(name));
            b.extend(name16("__TEXT"));
            b.extend((off as u64).to_le_bytes());
            b.extend((size as u64).to_le_bytes());
            words(&mut b, &[off, 2, 0, 0, flags, reserved1, reserved2, 0]);
        }
        words(
            &mut b,
            &[
                0x2,
                symtab_len,
                sym_off,
                syms.len() as u32,
                str_off,
                strtab.len() as u32,
            ],
        );
        let mut dysymtab = [0u32; 20];
        dysymtab[0] = 0xb;
        dysymtab[1] = dysymtab_len;
        dysymtab[14] = indirect_off;
        dysymtab[15] = 2;
        words(&mut b, &dysymtab);
        assert_eq!(b.len() as u32, text_off);
        words(&mut b, &text);
        b.extend([0u8; 24]); // stub bodies are never decoded
        b.extend(nlists);
        words(&mut b, &[14, 13]); // stub 0 → _strcpy, stub 1 → _rand
        b.extend(strtab);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::macho_with_calls;
    use super::*;

    #[test]
    fn module_names_from_object_paths() {
        for (path, module) in [
            (
                "/b/Build/Intermediates.noindex/Pods.build/Release-iphoneos/gRPC-Core.build/Objects-normal/arm64/tcp.o",
                "gRPC-Core",
            ),
            (
                "/b/Intermediates.noindex/App.build/Release-iphoneos/App.build/Objects-normal/arm64/AppDelegate.o",
                "App",
            ),
            ("/b/Build/libPods-BusRider-AHKActionSheet.a(AHKActionSheet.o)", "AHKActionSheet"),
            ("/b/Funkin/libApplicationMain.a(00866ed8_FlxFlicker.o)", "ApplicationMain"),
            ("/b/.build/arm64-apple-ios/release/FrameUp.build/AnyFULayout.o", "FrameUp"),
            ("/b/Build/Products/Release-iphoneos/FirebaseCore.o", "FirebaseCore"),
        ] {
            assert_eq!(module_of_object(path).as_deref(), Some(module), "{path}");
        }
    }

    #[test]
    fn function_lookup_respects_ranges() {
        let f = |start, end, m: &str| Function {
            start,
            end,
            module: m.to_string(),
        };
        let functions = vec![f(0x100, 0x180, "App"), f(0x200, 0x240, "grpc")];
        assert_eq!(function_at(&functions, 0x100), Some("App"));
        assert_eq!(function_at(&functions, 0x17c), Some("App"));
        assert_eq!(function_at(&functions, 0x180), None);
        assert_eq!(function_at(&functions, 0x23c), Some("grpc"));
        assert_eq!(function_at(&functions, 0x50), None);
    }

    #[test]
    fn calls_attributed_to_app_and_dependency() {
        let c = callers(&macho_with_calls(), &["_strcpy", "_rand"]).expect("debug map");
        assert_eq!(c.app_module.as_deref(), Some("App"));
        let strcpy = &c.by_symbol["_strcpy"];
        assert_eq!(strcpy.get("App"), Some(&1));
        assert_eq!(strcpy.get("Dep"), Some(&1));
        assert_eq!(c.by_symbol["_rand"].get("Dep"), Some(&1));
        assert_eq!(c.by_symbol["_rand"].len(), 1);
    }

    #[test]
    fn huge_stub_section_is_bounded_by_indirect_table() {
        // __stubs claims u64::MAX bytes of 1-byte stubs; the scan must stop at
        // the indirect symbol table instead of looping for ~2^64 iterations.
        let mut data = macho_with_calls();
        let stubs_hdr = 32 + 72 + 80;
        data[stubs_hdr + 40..stubs_hdr + 48].copy_from_slice(&u64::MAX.to_le_bytes());
        data[stubs_hdr + 72..stubs_hdr + 76].copy_from_slice(&1u32.to_le_bytes());
        data[stubs_hdr + 68..stubs_hdr + 72].copy_from_slice(&u32::MAX.to_le_bytes());
        let macho = MachO::parse(&data, 0).unwrap();
        assert!(stub_targets(&macho, &data, &["_strcpy"]).is_empty());
    }

    #[test]
    fn non_macho_has_no_callers() {
        assert_eq!(callers(b"not a binary", &["_strcpy"]), None);
    }
}
