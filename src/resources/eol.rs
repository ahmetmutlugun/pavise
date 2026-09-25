//! Bundled-library version detection and end-of-life lookup.
//!
//! Versions come from strings a library compiles into itself (OpenSSL's
//! `OpenSSL 1.1.1k  25 Mar 2021`, jQuery's license banner, …), since vendored
//! frameworks' Info.plists usually carry a template `1.0`. EOL status comes
//! from endoflife.date snapshots in `data/eol/`, refreshed by
//! `scripts/update-eol.sh` (weekly CI job), so results only change when a
//! snapshot update is merged — never with the scan date.

use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::types::{Finding, Severity};

/// Where a detector looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Mach-O binaries (frameworks, dylibs, or code linked into an executable).
    Native,
    /// Web assets: `.js`, `.css`, `.html`, `.jsbundle`.
    Web,
    /// .NET assemblies (`System.Private.CoreLib.dll`).
    Dotnet,
}

/// A version string a library embeds in itself.
struct Detector {
    /// endoflife.date product slug; `data/eol/<slug>.json` must exist.
    product: &'static str,
    /// Display name.
    library: &'static str,
    scope: Scope,
    /// Cheap literal prefilter; the regex runs only if the text contains it.
    needle: &'static str,
    /// Capture group 1 is the version (FFmpeg: libavformat major/minor).
    pattern: &'static str,
    /// Only files whose name (lowercase) contains this.
    file_hint: Option<&'static str>,
}

const DETECTORS: &[Detector] = &[
    Detector {
        product: "openssl",
        library: "OpenSSL",
        scope: Scope::Native,
        needle: "OpenSSL ",
        // `OpenSSL_version()` text; the date keeps prose mentions out.
        pattern: r"\bOpenSSL ([0-9]\.[0-9]+\.[0-9]+[a-z]{0,2})(?:-[a-z]+)? +[0-9]{1,2} [A-Z][a-z]{2} [0-9]{4}",
        file_hint: None,
    },
    Detector {
        product: "lua",
        library: "Lua",
        scope: Scope::Native,
        needle: "$LuaVersion: ",
        pattern: r"\$LuaVersion: Lua ([0-9]\.[0-9]+(?:\.[0-9]+)?)",
        file_hint: None,
    },
    Detector {
        product: "qt",
        library: "Qt",
        scope: Scope::Native,
        needle: "_endian",
        // `QLibraryInfo::build()`: `Qt 6.5.0 (arm64-little_endian-lp64 static …`
        pattern: r"\bQt ([0-9]\.[0-9]+\.[0-9]+) \([a-z0-9_]+-(?:little|big)_endian",
        file_hint: None,
    },
    Detector {
        product: "godot",
        library: "Godot",
        scope: Scope::Native,
        needle: "Godot Engine v",
        pattern: r"Godot Engine v([0-9]\.[0-9]+(?:\.[0-9]+)?)\.(?:stable|rc|beta|dev)",
        file_hint: None,
    },
    Detector {
        product: "unity",
        library: "Unity",
        scope: Scope::Native,
        needle: ".",
        // `2021.3.16f1`, `6000.0.23f1`; only inside UnityFramework.
        pattern: r"\b((?:20[0-9]{2}|6[0-9]{3})\.[0-9]+\.[0-9]+)[abfp][0-9]+\b",
        file_hint: Some("unityframework"),
    },
    Detector {
        product: "gstreamer",
        library: "GStreamer",
        scope: Scope::Native,
        needle: "GStreamer source release",
        // The core library stores its VERSION as a bare string.
        pattern: r"(?m)^(1\.[0-9]{1,2}\.[0-9]{1,2})$",
        file_hint: Some("gstreamer"),
    },
    Detector {
        product: "ffmpeg",
        library: "FFmpeg",
        scope: Scope::Native,
        needle: "Lavf",
        // LIBAVFORMAT_IDENT; mapped to a release by `ffmpeg_release`.
        pattern: r"\bLavf([0-9]{2})\.([0-9]{1,3})\.[0-9]{3}\b",
        file_hint: None,
    },
    Detector {
        product: "dotnet",
        library: ".NET",
        scope: Scope::Dotnet,
        needle: "+",
        // AssemblyInformationalVersion: `8.0.1+<commit sha>`
        pattern: r"\b([0-9]{1,2}\.[0-9]+\.[0-9]+)\+[0-9a-f]{40}\b",
        file_hint: Some("system.private.corelib"),
    },
    Detector {
        product: "react-native",
        library: "React Native",
        scope: Scope::Web,
        needle: "prerelease",
        // Libraries/Core/ReactNativeVersion.js in a plain-JS bundle (Hermes
        // bytecode keeps the numbers out of the string table).
        pattern: r"major:\s*0,\s*minor:\s*([0-9]+),\s*patch:\s*([0-9]+),\s*prerelease",
        file_hint: Some(".jsbundle"),
    },
    Detector {
        product: "jquery",
        library: "jQuery",
        scope: Scope::Web,
        needle: "jQuery",
        pattern: r"jQuery (?:JavaScript Library )?v([0-9]+\.[0-9]+\.[0-9]+)",
        file_hint: None,
    },
    Detector {
        product: "jquery-ui",
        library: "jQuery UI",
        scope: Scope::Web,
        needle: "jQuery UI",
        pattern: r"jQuery UI - v([0-9]+\.[0-9]+\.[0-9]+)",
        file_hint: None,
    },
    Detector {
        product: "bootstrap",
        library: "Bootstrap",
        scope: Scope::Web,
        needle: "Bootstrap v",
        pattern: r"Bootstrap v([0-9]+\.[0-9]+\.[0-9]+) \(https?://getbootstrap\.com",
        file_hint: None,
    },
    Detector {
        product: "vue",
        library: "Vue",
        scope: Scope::Web,
        needle: "ue",
        // `Vue.js v2.6.14` (2.x banner), `vue v3.3.4` (3.x build banner)
        pattern: r"\b(?:Vue\.js|vue) v([0-9]+\.[0-9]+\.[0-9]+)\b",
        file_hint: None,
    },
    Detector {
        product: "angularjs",
        library: "AngularJS",
        scope: Scope::Web,
        needle: "AngularJS v",
        pattern: r"AngularJS v(1\.[0-9]+\.[0-9]+)",
        file_hint: None,
    },
    Detector {
        product: "ionic",
        library: "Ionic",
        scope: Scope::Web,
        needle: "Ionic, v",
        // Ionic 1 bundle banner; Ionic 4+ ships no version string.
        pattern: r"Ionic, v([0-9]+\.[0-9]+\.[0-9]+)",
        file_hint: None,
    },
    Detector {
        product: "font-awesome",
        library: "Font Awesome",
        scope: Scope::Web,
        needle: "Font Awesome ",
        pattern: r"Font Awesome (?:Free |Pro )?([0-9]+\.[0-9]+\.[0-9]+)",
        file_hint: None,
    },
];

/// endoflife.date snapshots, one per product slug.
const SNAPSHOTS: &[(&str, &str)] = &[
    ("angularjs", include_str!("../../data/eol/angularjs.json")),
    ("bootstrap", include_str!("../../data/eol/bootstrap.json")),
    ("dotnet", include_str!("../../data/eol/dotnet.json")),
    ("ffmpeg", include_str!("../../data/eol/ffmpeg.json")),
    (
        "font-awesome",
        include_str!("../../data/eol/font-awesome.json"),
    ),
    ("godot", include_str!("../../data/eol/godot.json")),
    ("gstreamer", include_str!("../../data/eol/gstreamer.json")),
    ("ionic", include_str!("../../data/eol/ionic.json")),
    ("jquery", include_str!("../../data/eol/jquery.json")),
    ("jquery-ui", include_str!("../../data/eol/jquery-ui.json")),
    ("lua", include_str!("../../data/eol/lua.json")),
    ("openssl", include_str!("../../data/eol/openssl.json")),
    ("python", include_str!("../../data/eol/python.json")),
    ("qt", include_str!("../../data/eol/qt.json")),
    (
        "react-native",
        include_str!("../../data/eol/react-native.json"),
    ),
    ("unity", include_str!("../../data/eol/unity.json")),
    ("vue", include_str!("../../data/eol/vue.json")),
];

/// A library version found in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibraryVersion {
    /// Archive path of the file (or directory, for Python) it was found in.
    pub path: String,
    pub product: &'static str,
    pub library: &'static str,
    pub version: String,
    /// Found inside a Mach-O binary (a framework's own, or linked statically).
    pub native: bool,
}

fn compiled() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        DETECTORS
            .iter()
            .map(|d| Regex::new(d.pattern).expect("library detector regex"))
            .collect()
    })
}

/// Which detector scope a file falls under, if any.
pub fn scope_of(path: &str, is_macho: bool) -> Option<Scope> {
    if is_macho {
        return Some(Scope::Native);
    }
    let lower = path.to_lowercase();
    if lower.ends_with(".dll") {
        Some(Scope::Dotnet)
    } else if [".js", ".css", ".html", ".htm", ".jsbundle"]
        .iter()
        .any(|e| lower.ends_with(e))
    {
        Some(Scope::Web)
    } else {
        None
    }
}

/// Library versions embedded in one file's extracted text.
pub fn detect(text: &str, path: &str, scope: Scope) -> Vec<LibraryVersion> {
    let lower = path.to_lowercase();
    let mut out = Vec::new();
    for (d, re) in DETECTORS.iter().zip(compiled()) {
        if d.scope != scope
            || !d.file_hint.map_or(true, |h| lower.contains(h))
            || !text.contains(d.needle)
        {
            continue;
        }
        for c in re.captures_iter(text) {
            let version = match d.product {
                "ffmpeg" => match ffmpeg_release(&c[1], &c[2]) {
                    Some(v) => v.to_string(),
                    None => continue,
                },
                "react-native" => format!("0.{}.{}", &c[1], &c[2]),
                _ => c[1].to_string(),
            };
            out.push(LibraryVersion {
                path: path.to_string(),
                product: d.product,
                library: d.library,
                version,
                native: scope == Scope::Native,
            });
            // The GStreamer core stores one bare VERSION; other bare
            // versions in the same binary belong to something else.
            if d.product == "gstreamer" {
                break;
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// FFmpeg release for a libavformat version (first `Lavf` of each release).
/// Majors past the table are skipped rather than guessed: add rows as FFmpeg
/// releases (libavformat/version.h at the release tag).
fn ffmpeg_release(major: &str, minor: &str) -> Option<&'static str> {
    const TABLE: &[(u32, u32, &str)] = &[
        (58, 12, "4.0"),
        (58, 20, "4.1"),
        (58, 29, "4.2"),
        (58, 45, "4.3"),
        (58, 76, "4.4"),
        (59, 16, "5.0"),
        (59, 27, "5.1"),
        (60, 3, "6.0"),
        (60, 16, "6.1"),
        (61, 1, "7.0"),
        (61, 7, "7.1"),
    ];
    let (major, minor): (u32, u32) = (major.parse().ok()?, minor.parse().ok()?);
    if major < TABLE[0].0 || major > TABLE[TABLE.len() - 1].0 {
        return None;
    }
    TABLE
        .iter()
        .rev()
        .find(|(ma, mi, _)| (major, minor) >= (*ma, *mi))
        .map(|(_, _, r)| *r)
}

/// Embedded CPython, from its stdlib directory (`…/lib/python3.11/…`).
pub fn detect_python(paths: &[&str]) -> Vec<LibraryVersion> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^(.*/lib/python([0-9]\.[0-9]{1,2}))/").expect("python path regex")
    });
    let mut out: Vec<LibraryVersion> = paths
        .iter()
        .filter_map(|p| re.captures(p))
        .map(|c| LibraryVersion {
            path: c[1].to_string(),
            product: "python",
            library: "Python",
            version: c[2].to_string(),
            native: false,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    name: String,
    is_eol: bool,
    eol_from: Option<String>,
    is_eoes: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    releases: Vec<Release>,
}

fn snapshots() -> &'static HashMap<&'static str, Snapshot> {
    static MAP: OnceLock<HashMap<&'static str, Snapshot>> = OnceLock::new();
    MAP.get_or_init(|| {
        SNAPSHOTS
            .iter()
            .map(|(p, json)| {
                let s: Snapshot = serde_json::from_str(json).expect("data/eol snapshot");
                (*p, s)
            })
            .collect()
    })
}

/// Leading digits of each dotted component: `1.1.1k` → [1, 1, 1].
fn numeric_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map_while(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .collect()
}

/// An ended release line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    /// Release line, e.g. `1.1.1`, or how an untracked version relates to one.
    pub line: String,
    /// End of standard (free/community) support; endoflife.date omits it
    /// for some old lines.
    pub date: Option<String>,
    /// The vendor still sells extended support (OpenSSL premium, Qt ESR).
    pub paid_support: bool,
}

fn ended(r: &Release, line: String) -> Ended {
    Ended {
        line,
        date: r.eol_from.clone(),
        paid_support: r.is_eoes == Some(false),
    }
}

/// The release line `version` belongs to, if its standard support ended.
/// Paid extended support doesn't count: an app bundling the open-source build
/// gets no fixes from it. Lines are matched by longest numeric prefix
/// (`1.1.1k` → `1.1.1`, `8.0.1` → `8`). A version between two tracked lines
/// (a development release like GStreamer 1.19) has ended when both
/// neighbours have; one older than every tracked line, when the oldest has.
pub fn end_of_life(product: &str, version: &str) -> Option<Ended> {
    let releases = &snapshots().get(product)?.releases;
    let v = numeric_parts(version);
    if v.is_empty() {
        return None;
    }
    let matched = releases
        .iter()
        .filter(|r| {
            let c = numeric_parts(&r.name);
            !c.is_empty() && v.starts_with(&c)
        })
        .max_by_key(|r| numeric_parts(&r.name).len());
    if let Some(r) = matched {
        return r.is_eol.then(|| ended(r, r.name.clone()));
    }
    let mut lines: Vec<(Vec<u64>, &Release)> = releases
        .iter()
        .map(|r| (numeric_parts(&r.name), r))
        .filter(|(c, _)| !c.is_empty())
        .collect();
    lines.sort_by(|a, b| a.0.cmp(&b.0));
    let below = lines
        .iter()
        .rev()
        .find(|(c, _)| c.as_slice() < v.as_slice());
    let above = lines.iter().find(|(c, _)| c.as_slice() > v.as_slice());
    match (below, above) {
        (Some((_, lo)), Some((_, hi))) if lo.is_eol && hi.is_eol => {
            Some(ended(lo, format!("between {} and {}", lo.name, hi.name)))
        }
        (None, Some((_, oldest))) if oldest.is_eol => {
            Some(ended(oldest, format!("older than {}", oldest.name)))
        }
        _ => None,
    }
}

/// QS-SCA-001 for each library version on an ended release line, listing
/// every file it was found in (OpenSSL ships as both libssl and libcrypto).
pub fn findings(found: &[LibraryVersion]) -> Vec<Finding> {
    let mut groups: Vec<(&LibraryVersion, Vec<&str>)> = Vec::new();
    for lib in found {
        match groups
            .iter_mut()
            .find(|(g, _)| g.product == lib.product && g.version == lib.version)
        {
            Some((_, paths)) => paths.push(&lib.path),
            None => groups.push((lib, vec![&lib.path])),
        }
    }
    groups
        .into_iter()
        .filter_map(|(lib, paths)| {
            let e = end_of_life(lib.product, &lib.version)?;
            let when = e
                .date
                .as_ref()
                .map(|d| format!(" on {d}"))
                .unwrap_or_default();
            Some(Finding {
                id: "QS-SCA-001".to_string(),
                title: format!("End-of-Life {} Bundled", lib.library),
                description: format!(
                    "{} {} is bundled in the app. Its release line ({}) reached end of life{} \
                    and no longer receives public security fixes{}.",
                    lib.library,
                    lib.version,
                    e.line,
                    when,
                    if e.paid_support {
                        " (the vendor still sells extended support)"
                    } else {
                        ""
                    }
                ),
                severity: Severity::Warning,
                category: "sca".to_string(),
                cwe: Some("CWE-1104".to_string()),
                owasp_mobile: None,
                owasp_masvs: None,
                evidence: paths
                    .iter()
                    .map(|p| {
                        format!(
                            "{} {} in {}",
                            lib.library,
                            lib.version,
                            crate::binary::symbols::binary_name(p)
                        )
                    })
                    .collect(),
                remediation: Some(format!(
                    "Upgrade {} to a supported release line (see https://endoflife.date/{}).",
                    lib.library, lib.product
                )),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_detector_has_a_snapshot() {
        for d in DETECTORS {
            assert!(snapshots().contains_key(d.product), "{}", d.product);
        }
        let _ = compiled();
    }

    #[test]
    fn native_banners() {
        let text = "junk\nOpenSSL 1.1.1k  25 Mar 2021\n$LuaVersion: Lua 5.1.5  Copyright\n\
                    Qt 5.15.2 (arm64-little_endian-lp64 static release build; by Clang)\n\
                    Godot Engine v3.5.2.stable.official\nLavf60.3.100\nLavf57.%d.%d";
        let found = detect(text, "Payload/A.app/A", Scope::Native);
        let got: Vec<(&str, &str)> = found
            .iter()
            .map(|l| (l.product, l.version.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("ffmpeg", "6.0"),
                ("godot", "3.5.2"),
                ("lua", "5.1.5"),
                ("openssl", "1.1.1k"),
                ("qt", "5.15.2")
            ]
        );
        // Prose mentions and other files' bare versions are not banners.
        assert!(detect("built against OpenSSL 1.1.1", "x", Scope::Native).is_empty());
        assert!(detect(
            "GStreamer source release\n1.19.1",
            "Payload/A.app/A",
            Scope::Native
        )
        .is_empty());
        let gst = detect(
            "1.19.1\nGStreamer source release\n1.2.3",
            "Payload/U.app/Frameworks/gstreamer-1.0.0.framework/gstreamer-1.0.0",
            Scope::Native,
        );
        assert_eq!(gst.len(), 1);
        assert_eq!(gst[0].version, "1.19.1");
    }

    #[test]
    fn web_banners() {
        let text = "/*! jQuery v3.4.1 | (c) JS Foundation */ /*! jQuery UI - v1.12.1 */\n\
                    Bootstrap v4.6.0 (https://getbootstrap.com/) Vue.js v2.6.14 AngularJS v1.8.2 \
                    Font Awesome Free 5.15.4 by @fontawesome";
        let found = detect(text, "Payload/A.app/www/vendor.js", Scope::Web);
        let got: Vec<&str> = found.iter().map(|l| l.product).collect();
        assert_eq!(
            got,
            [
                "angularjs",
                "bootstrap",
                "font-awesome",
                "jquery",
                "jquery-ui",
                "vue"
            ]
        );
        let rn = detect(
            "exports.version={major:0,minor:71,patch:4,prerelease:null}",
            "Payload/A.app/main.jsbundle",
            Scope::Web,
        );
        assert_eq!(rn[0].version, "0.71.4");
    }

    #[test]
    fn python_from_stdlib_path() {
        let found = detect_python(&[
            "Payload/A.app/Frameworks/Python.framework/lib/python3.8/os.py",
            "Payload/A.app/Frameworks/Python.framework/lib/python3.8/json/__init__.py",
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].version, "3.8");
    }

    #[test]
    fn ffmpeg_mapping() {
        assert_eq!(ffmpeg_release("60", "3"), Some("6.0"));
        assert_eq!(ffmpeg_release("60", "20"), Some("6.1"));
        assert_eq!(ffmpeg_release("58", "76"), Some("4.4"));
        assert_eq!(ffmpeg_release("62", "3"), None);
        assert_eq!(ffmpeg_release("57", "83"), None);
    }

    #[test]
    fn release_line_matching() {
        // Against the shipped snapshots; these lines ended years ago.
        assert!(end_of_life("openssl", "1.1.1k").is_some());
        let e = end_of_life("openssl", "1.1.1w").unwrap();
        assert_eq!(e.line, "1.1.1");
        assert!(e.paid_support);
        assert!(end_of_life("openssl", "3.5.1").is_none());
        assert!(end_of_life("python", "3.8").is_some());
        assert!(end_of_life("jquery", "1.12.4").is_some());
        assert!(
            end_of_life("gstreamer", "1.19.1").is_some(),
            "dev release between EOL lines"
        );
        assert!(end_of_life("nonexistent", "1.0").is_none());
    }
}
