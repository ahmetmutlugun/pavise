// Pavise Security Report — Typst template
// Data is loaded from scan_report.json written to the same temp directory.
#let data = json("scan_report.json")

// ─── Design System Tokens ─────────────────────────────────────────────────────
// Colors
#let c-high   = rgb("#dc2626")
#let c-warn   = rgb("#d97706")
#let c-info   = rgb("#2563eb")
#let c-secure = rgb("#16a34a")
#let c-accent = rgb("#1e3a5f")
#let c-bg     = rgb("#f8fafc")
#let c-border = rgb("#cbd5e1")
#let c-muted  = rgb("#64748b")
#let c-text   = rgb("#1e293b")
#let c-purple = rgb("#7c3aed")
#let c-teal   = rgb("#0891b2")

// Border radius
#let r-small  = 3pt
#let r-medium = 4pt
#let r-large  = 6pt

// Box inset (padding)
#let pad-compact   = (x: 6pt, y: 4pt)
#let pad-standard  = (x: 9pt, y: 6pt)
#let pad-spacious  = (x: 10pt, y: 8pt)

// Stroke styles
#let stroke-border = 0.5pt + c-border
#let stroke-accent(col) = 1pt + col.lighten(60%)

// Spacing
#let space-xs = 0.3em
#let space-sm = 0.4em
#let space-md = 0.6em
#let space-lg = 0.8em
#let space-xl = 1em

// Gutter sizes
#let gutter-compact  = 0.4em
#let gutter-standard = 0.5em
#let gutter-spacious = 0.7em

// ─── Helpers ──────────────────────────────────────────────────────────────────
#let sev-color(s) = {
  if s == "high"         { c-high }
  else if s == "warning" { c-warn }
  else if s == "info"    { c-info }
  else                   { c-secure }
}

#let grade-color(g) = {
  if g == "A"      { c-secure }
  else if g == "B" { rgb("#22c55e") }
  else if g == "C" { rgb("#f59e0b") }
  else if g == "D" { rgb("#f97316") }
  else             { c-high }
}

#let badge(s) = box(
  fill: sev-color(s),
  inset: pad-compact,
  radius: r-small,
  text(size: 7.5pt, weight: "bold", fill: white)[
    #upper(if s == "warning" { "WARN" } else { s })
  ],
)

// Safe string truncation (byte-index based; safe for ASCII paths/keys/hashes).
#let trunc(s, n) = {
  if type(s) != str { return "—" }
  if s.len() > n { s.slice(0, n) + "…" } else { s }
}

// Render an Option<String> (null → fallback).
#let opt(v, fallback: "—") = {
  if v == none { fallback } else { str(v) }
}

// Censor a secret value: show the first `visible` characters then bullets.
// This prevents full secrets from being embedded in PDF reports.
#let censor(s, visible: 8) = {
  if type(s) != str or s.len() == 0 { return [—] }
  let n = calc.min(s.len(), visible)
  let prefix = s.slice(0, n)
  text(font: "DejaVu Sans Mono", size: 7.5pt)[#prefix#text(fill: c-muted)[••••••••]]
}

// Monospace text that wraps (unlike raw() which does not wrap in inline mode).
#let mono(s) = text(
  font: "DejaVu Sans Mono",
  size: 7.5pt,
)[#s]

#let tbl-fill(col, row) = {
  if row == 0    { rgb("#334155") }
  else if calc.odd(row) { white }
  else           { c-bg }
}

// Shared protection grid used for main + framework binaries.
#let prot-grid(protections) = grid(
  columns: (1fr, 1fr),
  gutter: gutter-standard,
  ..protections.map(p => {
    let ok  = p.enabled
    let col = if ok { c-secure } else { c-high }
    block(
      width: 100%,
      fill: col.lighten(92%),
      stroke: stroke-accent(col),
      inset: pad-standard,
      radius: r-medium,
    )[
      #text(fill: col, weight: "bold", size: 9pt)[
        #if ok [✓] else [✗] #p.name
      ]
      #linebreak()
      #text(size: 7.5pt, fill: c-muted)[#p.description]
    ]
  }),
)

// Extract the last path component as a display name.
#let basename(path) = {
  let parts = path.split("/").filter(s => s != "")
  if parts.len() > 0 { parts.last() } else { path }
}

// Section header block.
#let section-header(title) = block(
  width: 100%,
  fill: c-accent,
  inset: (x: 10pt, y: 7pt),
  radius: r-medium,
  text(size: 12pt, weight: "bold", fill: white)[#title],
)

// Section header with keep-with-next guard.
//
// Strategy: wrap the section header plus a silent 3 em "phantom" spacer in a
// breakable:false block so the whole unit (~65 pt) must fit on the page.
// If less than ~65 pt remain the block moves to the next page, keeping the
// header at the top of a fresh page right above its table.
// The v(-3em) that follows cancels the phantom so the table starts immediately
// below the header without any extra gap.
#let section-start(title) = {
  v(space-xl)
  block(breakable: false)[
    #section-header(title)
    // Silent spacer — invisible but contributes to block height so the
    // header never gets stranded alone at the bottom of a page.
    #box(height: 3em, width: 0pt)[]
  ]
  v(-3em)
  v(space-sm)
}

// ─── Page setup ───────────────────────────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (left: 1.8cm, right: 1.8cm, top: 2.8cm, bottom: 2.2cm),
  header: context {
    set text(size: 8pt, fill: c-muted)
    [Pavise Security Report #h(1fr) #data.app_info.name v#data.app_info.version]
    v(-4pt)
    line(length: 100%, stroke: stroke-border)
  },
  footer: context {
    line(length: 100%, stroke: stroke-border)
    v(-4pt)
    set text(size: 8pt, fill: c-muted)
    [Confidential — Static Security Analysis
     #h(1fr)
     Page #counter(page).display("1 of 1", both: true)]
  },
)

#set text(
  font: "Liberation Sans",
  size: 10pt,
  fill: c-text,
)
#set par(justify: true)

// ─── Title block ──────────────────────────────────────────────────────────────
#grid(
  columns: (1fr, auto),
  gutter: 1.5em,
  align(horizon)[
    #text(size: 22pt, weight: "bold")[#data.app_info.name]
    #linebreak()
    // Bundle identifier: use monospace at reduced size so long IDs don't overflow.
    #text(
      size: 8.5pt,
      fill: c-muted,
      font: "DejaVu Sans Mono",
    )[#trunc(data.app_info.identifier, 60)]
    #v(0.4em)
    #set text(size: 9pt)
    *Version* #data.app_info.version
    #h(1.5em) *Build* #data.app_info.build
    #h(1.5em) *Min iOS* #data.app_info.min_os_version
    #h(1.5em) *Platform* #str(data.app_info.platform)
    #h(1.5em) *SDK* #data.app_info.sdk_name
  ],
  box(
    fill: grade-color(data.grade),
    inset: (x: 18pt, y: 14pt),
    radius: 8pt,
    align(center)[
      #text(size: 40pt, weight: "black", fill: white)[#data.grade]
      #v(-6pt)
      #text(size: 10pt, fill: white.transparentize(25%))[#data.security_score / 100]
    ],
  ),
)

#v(space-md)
#line(length: 100%, stroke: 2pt + c-accent)
#v(space-lg)

// ─── Summary cards ────────────────────────────────────────────────────────────
#let high-count = (
  data.findings.filter(f => f.severity == "high").len()
  + data.secrets.filter(s => s.severity == "high").len()
)
#let warn-count = (
  data.findings.filter(f => f.severity == "warning").len()
  + data.secrets.filter(s => s.severity == "warning").len()
)
#let info-count = data.findings.filter(f => f.severity == "info").len()

#let stat-card(val, lbl, col) = block(
  width: 100%,
  fill: col.lighten(92%),
  stroke: stroke-accent(col),
  inset: pad-spacious,
  radius: r-large,
  align(center)[
    #text(size: 26pt, weight: "bold", fill: col)[#val]
    #v(-4pt)
    #text(size: 7.5pt, fill: c-muted, weight: "bold")[#upper(lbl)]
  ],
)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr, 1fr),
  gutter: gutter-standard,
  stat-card(high-count,          "High",     c-high),
  stat-card(warn-count,          "Warning",  c-warn),
  stat-card(info-count,          "Info",     c-info),
  stat-card(data.secrets.len(),  "Secrets",  c-purple),
  stat-card(data.trackers.len(), "Trackers", c-teal),
)

#v(space-lg)

// ─── File metadata ────────────────────────────────────────────────────────────
// SHA-256 is 64 hex chars and cannot break inside raw(). We give it its own
// full-width row and use plain monospace text so it wraps if ever needed.
#block(
  width: 100%,
  fill: c-bg,
  stroke: stroke-border,
  inset: pad-spacious,
  radius: r-medium,
)[
  #set text(size: 8.5pt)
  #grid(
    columns: (auto, 1fr, auto, 1fr),
    gutter: (gutter-compact, gutter-spacious),
    text(fill: c-muted)[*MD5*],
    mono(data.file_hashes.md5),
    text(fill: c-muted)[*Size*],
    [#calc.round(data.file_hashes.size_bytes / 1048576, digits: 2) MB],
    text(fill: c-muted)[*SHA1*],
    mono(data.file_hashes.sha1),
    [],
    [],
  )
  #v(space-xs)
  #grid(
    columns: (auto, 1fr),
    gutter: gutter-compact,
    text(fill: c-muted)[*SHA256*],
    mono(data.file_hashes.sha256),
  )
]

// ─── OWASP Mobile Top 10 Summary ─────────────────────────────────────────────
#let owasp-cats = (
  ("M1",  "Improper Credential Usage"),
  ("M2",  "Inadequate Supply Chain Security"),
  ("M3",  "Insecure Authentication/Authorization"),
  ("M4",  "Insufficient Input/Output Validation"),
  ("M5",  "Insecure Communication"),
  ("M6",  "Inadequate Privacy Controls"),
  ("M7",  "Insufficient Binary Protections"),
  ("M8",  "Security Misconfiguration"),
  ("M9",  "Insecure Data Storage"),
  ("M10", "Insufficient Cryptography"),
)
#let owasp-sum = data.owasp_summary

#section-start("OWASP Mobile Top 10 Coverage")

#grid(
  columns: (1fr, 1fr),
  gutter: gutter-standard,
  ..owasp-cats.map(cat => {
    let key    = cat.at(0)
    let label  = cat.at(1)
    let ids    = owasp-sum.at(key, default: ())
    let count  = ids.len()
    let col    = if count > 0 { c-high } else { c-secure }
    block(
      width: 100%,
      fill: col.lighten(92%),
      stroke: stroke-accent(col),
      inset: pad-standard,
      radius: r-small,
      height: 3.5em,
    )[
      #grid(
        columns: (1fr, auto),
        gutter: gutter-compact,
        align: (left, right),
        text(weight: "bold", size: 9pt, fill: col)[#key] + h(0.3em) +
        text(size: 8.5pt, fill: c-text)[#label],
        if count > 0 {
          box(
            fill: col,
            inset: pad-compact,
            radius: r-large,
            text(size: 7.5pt, weight: "bold", fill: white)[#count],
          )
        } else {
          text(size: 8pt, fill: c-secure)[✓]
        },
      )
    ]
  }),
)

// ─── Security Findings ────────────────────────────────────────────────────────
#if data.findings.len() > 0 [
  #section-start("Security Findings")

  #let sorted = data.findings.sorted(key: f => (
    if f.severity == "high"    { 0 }
    else if f.severity == "warning" { 1 }
    else if f.severity == "info"    { 2 }
    else { 3 }
  ))

  #table(
    columns: (auto, auto, 1fr, auto),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[ID],
    text(weight: "bold", fill: white, size: 8.5pt)[SEV],
    text(weight: "bold", fill: white, size: 8.5pt)[TITLE · DESCRIPTION · EVIDENCE · REMEDIATION],
    text(weight: "bold", fill: white, size: 8.5pt)[REFS],
    ..sorted.map(f => {
      let ev        = f.evidence.at(0, default: "")
      let desc      = f.description
      let rem       = f.at("remediation",  default: none)
      let cwe       = f.at("cwe",          default: none)
      let owasp     = f.at("owasp_mobile", default: none)
      let masvs     = f.at("owasp_masvs",  default: none)
      let ref-parts = (cwe, owasp, masvs).filter(x => x != none)
      (
        text(size: 8pt, fill: c-muted)[#f.id],
        badge(f.severity),
        [
          #text(weight: "bold", size: 9pt)[#f.title]
          #if desc.len() > 0 [
            #linebreak()
            #text(size: 8pt, fill: c-text)[#trunc(desc, 130)]
          ]
          #if ev.len() > 0 [
            #linebreak()
            #mono(trunc(ev, 90))
          ]
          #if rem != none [
            #linebreak()
            #text(size: 7.5pt, fill: c-secure, style: "italic")[→ #trunc(rem, 100)]
          ]
        ],
        [
          #for r in ref-parts [
            #text(size: 7.5pt)[#r]
            #linebreak()
          ]
          #if ref-parts.len() == 0 [#text(size: 8pt)[—]]
        ],
      )
    }).flatten()
  )
]

// ─── Secrets ──────────────────────────────────────────────────────────────────
#if data.secrets.len() > 0 [
  #section-start("Secrets Detected")

  #table(
    columns: (auto, auto, 1fr),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[RULE],
    text(weight: "bold", fill: white, size: 8.5pt)[SEV],
    text(weight: "bold", fill: white, size: 8.5pt)[TITLE · VALUE (redacted) · FILE],
    ..data.secrets.map(s => {
      let fp = s.at("file_path", default: none)
      (
        text(size: 8pt, fill: c-muted)[#s.rule_id],
        badge(s.severity),
        [
          #text(weight: "bold", size: 9pt)[#s.title]
          #linebreak()
          #text(fill: c-purple)[#censor(s.matched_value, visible: 8)]
          #if fp != none [
            #linebreak()
            #text(size: 7.5pt, fill: c-muted)[#trunc(fp, 70)]
          ]
        ],
      )
    }).flatten()
  )
]

// ─── Firebase Configuration ───────────────────────────────────────────────────
#if data.firebase != none [
  #let fb = data.firebase
  #section-start("Firebase Configuration")

  #block(
    width: 100%,
    fill: c-warn.lighten(92%),
    stroke: stroke-accent(c-warn),
    inset: pad-spacious,
    radius: r-medium,
  )[
    #set text(size: 9pt)
    #text(size: 8pt, fill: c-warn, weight: "bold")[
      ⚠ Firebase credentials are embedded in the application bundle.
    ]
    #v(space-sm)
    #grid(
      columns: (auto, 1fr, auto, 1fr),
      gutter: (gutter-compact, gutter-spacious),
      text(fill: c-muted)[*Project ID*],
      [#opt(fb.at("project_id",    default: none))],
      text(fill: c-muted)[*Database URL*],
      [#trunc(opt(fb.at("database_url", default: none)), 45)],
      text(fill: c-muted)[*Bundle ID*],
      [#trunc(opt(fb.at("bundle_id",    default: none)), 55)],
      text(fill: c-muted)[*App ID*],
      // Google App IDs can be long (e.g. "1:123456789:ios:abc123…") — truncate.
      [#trunc(opt(fb.at("google_app_id", default: none)), 45)],
      text(fill: c-muted)[*API Key*],
      // Partially redact — show enough to identify, not enough to abuse.
      {
        let k = fb.at("api_key", default: none)
        if k != none {
          censor(k, visible: 12)
        } else { [—] }
      },
    )
  ]
]

// ─── Main Binary Protections ──────────────────────────────────────────────────
#if data.main_binary != none [
  #let bin = data.main_binary
  #section-start("Binary Protections — " + bin.arch + " (main binary)")
  #prot-grid(bin.protections)
]

// ─── Framework Binary Protections ─────────────────────────────────────────────
#if data.framework_binaries.len() > 0 [
  #section-start("Framework Binary Protections")

  #for bin in data.framework_binaries [
    #block(
      width: 100%,
      fill: c-bg,
      stroke: stroke-border,
      inset: pad-standard,
      radius: r-small,
    )[
      #text(weight: "bold", size: 9pt)[#basename(bin.path)]
      #h(space-md)
      #text(size: 8pt, fill: c-muted)[#bin.arch]
    ]
    #v(space-xs)
    #prot-grid(bin.protections)
    #v(space-md)
  ]
]

// ─── Trackers ─────────────────────────────────────────────────────────────────
#if data.trackers.len() > 0 [
  #section-start("Trackers Detected")

  #table(
    columns: (1fr, auto, auto),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[NAME],
    text(weight: "bold", fill: white, size: 8.5pt)[CATEGORIES],
    text(weight: "bold", fill: white, size: 8.5pt)[DETECTED VIA],
    ..data.trackers.map(t => (
      text(weight: "bold", size: 9pt)[#t.name],
      text(size: 8.5pt)[#t.categories.join(", ")],
      text(size: 8pt, fill: c-muted)[#trunc(t.detection_evidence, 60)],
    )).flatten()
  )
]

// ─── CVE Findings ─────────────────────────────────────────────────────────────
#let cve-findings = data.findings.filter(f => f.id.starts-with("QS-CVE-"))
#if cve-findings.len() > 0 [
  #section-start("Known Vulnerabilities (CVE)")

  #table(
    columns: (auto, auto, 1fr, auto),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[ID],
    text(weight: "bold", fill: white, size: 8.5pt)[SEV],
    text(weight: "bold", fill: white, size: 8.5pt)[VULNERABILITY],
    text(weight: "bold", fill: white, size: 8.5pt)[EVIDENCE],
    ..cve-findings.map(f => {
      let ev = f.evidence.at(0, default: "")
      (
        text(size: 8pt, fill: c-muted)[#f.id],
        badge(f.severity),
        text(size: 9pt)[#f.title],
        text(size: 8pt, fill: c-muted)[#trunc(ev, 60)],
      )
    }).flatten()
  )
]

// ─── Domain Intelligence ──────────────────────────────────────────────────────
#if data.domain_intel.len() > 0 [
  #section-start("Domain Intelligence (--network)")

  #let ofac-count = data.domain_intel.filter(d => d.is_ofac_sanctioned).len()
  #if ofac-count > 0 [
    #block(
      width: 100%,
      fill: c-high.lighten(92%),
      stroke: stroke-accent(c-high),
      inset: pad-standard,
      radius: r-small,
    )[
      #text(size: 8.5pt, fill: c-high, weight: "bold")[
        ⚠ #ofac-count OFAC-sanctioned server(s) detected — potential export control violation.
      ]
    ]
    #v(space-sm)
  ]

  #table(
    columns: (1fr, auto, auto, auto, auto),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: (col, row) => {
      if row == 0 { rgb("#334155") }
      else {
        let d = data.domain_intel.at(row - 1)
        if d.is_ofac_sanctioned { c-high.lighten(88%) }
        else if calc.odd(row) { white }
        else { c-bg }
      }
    },
    text(weight: "bold", fill: white, size: 8.5pt)[DOMAIN],
    text(weight: "bold", fill: white, size: 8.5pt)[IP],
    text(weight: "bold", fill: white, size: 8.5pt)[COUNTRY],
    text(weight: "bold", fill: white, size: 8.5pt)[ISP],
    text(weight: "bold", fill: white, size: 8.5pt)[OFAC],
    ..data.domain_intel.map(d => (
      text(size: 8.5pt)[#d.domain],
      text(size: 8pt, fill: c-muted)[#opt(d.at("ip",      default: none))],
      text(size: 8.5pt)[#opt(d.at("country", default: none))],
      text(size: 8pt, fill: c-muted)[#trunc(opt(d.at("isp", default: none)), 30)],
      if d.is_ofac_sanctioned {
        text(weight: "bold", fill: c-high, size: 8.5pt)[⚠ YES]
      } else {
        text(size: 8.5pt, fill: c-secure)[—]
      },
    )).flatten()
  )
] else if data.domains.len() > 0 [
  #section-start("Extracted Domains")
  #text(size: 8pt, fill: c-muted)[
    Run with #raw("--network") for geolocation and OFAC analysis.
  ]
  #v(space-sm)

  #table(
    columns: (1fr, auto),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[DOMAIN],
    text(weight: "bold", fill: white, size: 8.5pt)[CONTEXT],
    ..data.domains.map(d => (
      text(size: 8.5pt)[#d.domain],
      text(size: 8pt, fill: c-muted)[#d.context],
    )).flatten()
  )
]

// ─── Emails ───────────────────────────────────────────────────────────────────
#if data.emails.len() > 0 [
  #section-start("Extracted Email Addresses")

  #block(
    width: 100%,
    fill: c-bg,
    stroke: stroke-border,
    inset: pad-spacious,
    radius: r-medium,
  )[
    #set text(size: 8.5pt)
    #data.emails.map(e => raw(e)).join([, #h(space-xs)])
  ]
]

// ─── Permissions ──────────────────────────────────────────────────────────────
#if data.app_info.permissions.len() > 0 [
  #section-start("Permissions")

  #table(
    columns: (1fr, auto, 2fr, 1.5fr),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[KEY],
    text(weight: "bold", fill: white, size: 8.5pt)[STATUS],
    text(weight: "bold", fill: white, size: 8.5pt)[DESCRIPTION],
    text(weight: "bold", fill: white, size: 8.5pt)[REASON],
    ..data.app_info.permissions.map(p => (
      text(size: 8.5pt)[#p.key],
      text(
        size: 8.5pt,
        fill: if p.status == "used" { c-warn } else { c-muted },
      )[#p.status],
      text(size: 8.5pt, fill: c-muted)[#trunc(p.description, 70)],
      text(size: 8.5pt, fill: c-muted)[#trunc(p.reason, 60)],
    )).flatten()
  )
]

// ─── Provisioning Profile ─────────────────────────────────────────────────────
#if data.provisioning != none [
  #let prov = data.provisioning
  #section-start("Provisioning Profile")

  #block(
    width: 100%,
    fill: c-high.lighten(92%),
    stroke: stroke-accent(c-high),
    inset: pad-spacious,
    radius: r-medium,
  )[
    #set text(size: 9pt)
    #grid(
      columns: (auto, 1fr, auto, 1fr),
      gutter: (gutter-compact, gutter-spacious),
      text(fill: c-muted)[*Type*],
      text(weight: "bold", fill: c-high)[#upper(prov.profile_type)],
      text(fill: c-muted)[*Devices*],
      text(fill: if prov.provisioned_device_count > 0 { c-warn } else { c-muted })[
        #str(prov.provisioned_device_count) provisioned
      ],
      text(fill: c-muted)[*Profile Name*],
      [#trunc(opt(prov.at("name",            default: none)), 50)],
      text(fill: c-muted)[*Team Name*],
      [#opt(prov.at("team_name",             default: none))],
      text(fill: c-muted)[*Team ID*],
      mono(opt(prov.at("team_id",            default: none))),
      text(fill: c-muted)[*Expires*],
      [#opt(prov.at("expiration_date",       default: none))],
    )
  ]
]

// ─── Framework Components (SCA) ───────────────────────────────────────────────
#if data.framework_components.len() > 0 [
  #section-start("Framework Components (SCA)")

  #table(
    columns: (1fr, auto, 1fr),
    inset: (x: 7pt, y: 5pt),
    stroke: stroke-border,
    fill: tbl-fill,
    text(weight: "bold", fill: white, size: 8.5pt)[NAME],
    text(weight: "bold", fill: white, size: 8.5pt)[VERSION],
    text(weight: "bold", fill: white, size: 8.5pt)[BUNDLE ID],
    ..data.framework_components.map(c => (
      text(weight: "bold", size: 9pt)[#c.name],
      text(size: 8.5pt)[#opt(c.at("version",   default: none))],
      text(size: 8pt, fill: c-muted)[#trunc(opt(c.at("bundle_id", default: none)), 55)],
    )).flatten()
  )
]

// ─── Scan metadata footer ─────────────────────────────────────────────────────
#v(space-xl + space-lg)
#line(length: 100%, stroke: stroke-border)
#v(space-sm)
#set text(size: 8pt, fill: c-muted)
#grid(
  columns: (1fr, auto),
  [Generated by *Pavise* static analysis — results are indicative only.],
  [Scan duration: #data.scan_duration_ms ms],
)
