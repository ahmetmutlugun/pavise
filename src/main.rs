#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use pavise::{
    baseline,
    report::{html, json, pdf, sarif},
    resolve_rules_dir, scan_ipa,
    types::{Finding, ScanReport, Severity},
    ScanOptions,
};

#[derive(Parser, Debug)]
#[command(
    name = "pavise",
    about = "Fast mobile app static security analysis",
    long_about = "Pavise performs static security analysis on iOS IPA and Android APK files.\nTargets <3s scan time with coverage equivalent to MobSF."
)]
struct Cli {
    /// Path to IPA or APK file to scan
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Write report to file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    format: OutputFormat,

    /// Custom rules directory
    #[arg(short, long, value_name = "DIR")]
    rules: Option<PathBuf>,

    /// Suppress all output except the score line
    #[arg(short, long)]
    quiet: bool,

    /// Include per-check timing information
    #[arg(short, long)]
    verbose: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Minimum severity level to report
    #[arg(long, value_enum, default_value = "info")]
    min_severity: SeverityArg,

    /// Perform DNS resolution and IP geolocation for extracted domains.
    /// Requires network access. Uses ip-api.com (free, no key needed).
    #[arg(long)]
    network: bool,

    /// Path to a previous scan JSON report to diff against.
    /// Emits [NEW] and [FIXED] prefixes in the summary and adds a baseline_diff
    /// section to all output formats.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Json,
    Sarif,
    Html,
    Pdf,
}

#[derive(ValueEnum, Clone, Debug)]
enum SeverityArg {
    High,
    Warning,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::High => Severity::High,
            SeverityArg::Warning => Severity::Warning,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        "pavise=debug"
    } else {
        "pavise=warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let rules_dir = resolve_rules_dir(cli.rules.as_deref());
    if !rules_dir.exists() {
        eprintln!(
            "{} Rules directory not found: {}",
            "Warning:".yellow(),
            rules_dir.display()
        );
    }

    let min_severity = Severity::from(cli.min_severity.clone());

    let opts = ScanOptions {
        rules_dir,
        min_severity,
        network: cli.network,
    };

    // Validate the file exists and is within a sane size limit before scanning.
    const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
    match std::fs::metadata(&cli.file) {
        Ok(meta) => {
            if !meta.is_file() {
                eprintln!("{} '{}' is not a file", "Error:".red(), cli.file.display());
                std::process::exit(2);
            }
            if meta.len() == 0 {
                eprintln!("{} File is empty: {}", "Error:".red(), cli.file.display());
                std::process::exit(2);
            }
            if meta.len() > MAX_FILE_BYTES {
                eprintln!(
                    "{} File exceeds maximum size of 2 GiB: {} ({} bytes)",
                    "Error:".red(),
                    cli.file.display(),
                    meta.len()
                );
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!(
                "{} Cannot access '{}': {}",
                "Error:".red(),
                cli.file.display(),
                e
            );
            std::process::exit(2);
        }
    }

    let ext = cli
        .file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut report = match ext.as_str() {
        "ipa" => scan_ipa(&cli.file, &opts).context("IPA scan failed")?,
        "apk" => {
            eprintln!("{} Android APK analysis coming in Phase 2.", "Info:".cyan());
            std::process::exit(2);
        }
        _ => {
            eprintln!(
                "{} Unrecognized file extension '{}'. Expected .ipa or .apk",
                "Error:".red(),
                ext
            );
            std::process::exit(2);
        }
    };

    // Baseline diff (optional)
    if let Some(ref baseline_path) = cli.baseline {
        match std::fs::read_to_string(baseline_path) {
            Ok(baseline_json) => match serde_json::from_str::<ScanReport>(&baseline_json) {
                Ok(baseline_report) => {
                    let diff = baseline::compare(&report, &baseline_report);
                    report.baseline_diff = Some(diff);
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to parse baseline report: {}",
                        "Warning:".yellow(),
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "{} Could not read baseline file '{}': {}",
                    "Warning:".yellow(),
                    baseline_path.display(),
                    e
                );
            }
        }
    }

    if !cli.quiet {
        print_summary(&report, &cli.min_severity, cli.verbose);
    } else {
        println!(
            "{}/100 {} — {} high, {} warning findings",
            report.security_score,
            report.grade,
            report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Warning)
                .count(),
        );
    }

    let has_high = report.findings.iter().any(|f| f.severity == Severity::High)
        || report.secrets.iter().any(|s| s.severity == Severity::High);

    // PDF is binary — handle separately before the text report path.
    if matches!(cli.format, OutputFormat::Pdf) {
        let pdf_bytes = pdf::to_bytes(&report).context("PDF generation failed")?;
        match &cli.output {
            Some(output_path) => {
                std::fs::write(output_path, &pdf_bytes)
                    .with_context(|| format!("Failed to write PDF to {}", output_path.display()))?;
                if !cli.quiet {
                    eprintln!(
                        "{} PDF report written to {}",
                        "✓".green(),
                        output_path.display()
                    );
                }
            }
            None => {
                eprintln!("{} PDF format requires --output <FILE>", "Error:".red());
                std::process::exit(2);
            }
        }
        std::process::exit(if has_high { 1 } else { 0 });
    }

    let report_str = match cli.format {
        OutputFormat::Json => json::to_string(&report)?,
        OutputFormat::Sarif => sarif::to_string(&report)?,
        OutputFormat::Html => html::to_string(&report)?,
        OutputFormat::Pdf => unreachable!(),
    };

    if let Some(output_path) = &cli.output {
        std::fs::write(output_path, &report_str)
            .with_context(|| format!("Failed to write report to {}", output_path.display()))?;
        if !cli.quiet {
            eprintln!(
                "{} Report written to {}",
                "✓".green(),
                output_path.display()
            );
        }
    } else if !cli.quiet {
        println!("{}", report_str);
    }

    std::process::exit(if has_high { 1 } else { 0 });
}

fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn print_summary(report: &ScanReport, min_severity: &SeverityArg, verbose: bool) {
    // Print baseline diff summary if available
    if let Some(ref diff) = report.baseline_diff {
        let delta_str = if diff.score_delta > 0 {
            format!("+{}", diff.score_delta).green().to_string()
        } else if diff.score_delta < 0 {
            format!("{}", diff.score_delta).red().to_string()
        } else {
            "±0".to_string()
        };

        eprintln!(
            "  {} Score delta: {}  │  {} new findings  │  {} fixed findings  │  {} new secrets  │  {} fixed secrets{}",
            "Baseline Diff:".bold(),
            delta_str,
            format!("{}", diff.new_findings.len()).red(),
            format!("{}", diff.fixed_findings.len()).green(),
            format!("{}", diff.new_secrets).red(),
            format!("{}", diff.fixed_secrets).green(),
            if diff.grade_changed { "  │  grade changed".yellow().to_string() } else { String::new() }
        );
        eprintln!();
    }
    let grade_colored = match report.grade.as_str() {
        "A" => report.grade.bright_green().bold(),
        "B" => report.grade.green().bold(),
        "C" => report.grade.yellow().bold(),
        "D" => report.grade.red().bold(),
        _ => report.grade.bright_red().bold(),
    };

    eprintln!();
    eprintln!(
        "  {} {} — {} v{} ({})",
        "Pavise".bold(),
        "▶".bright_blue(),
        report.app_info.name.bold(),
        report.app_info.version,
        report.app_info.identifier
    );
    eprintln!(
        "  Security Score: {} {} ({}/100)  │  Scan: {}ms",
        grade_colored,
        score_bar(report.security_score),
        report.security_score,
        report.scan_duration_ms
    );

    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count()
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::High)
            .count();
    let warn_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count()
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::Warning)
            .count();
    let info_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    eprintln!(
        "  Findings: {} high  {} warning  {} info  │  {} trackers  │  {} secrets",
        format!("{}", high_count).red().bold(),
        format!("{}", warn_count).yellow(),
        format!("{}", info_count).white(),
        report.trackers.len(),
        report.secrets.len(),
    );

    eprintln!(
        "  Hashes:  MD5 {}  SHA256 {}",
        &report.file_hashes.md5[..8],
        &report.file_hashes.sha256[..16]
    );

    let shown_severities: Vec<Severity> = match min_severity {
        SeverityArg::High => vec![Severity::High],
        SeverityArg::Warning => vec![Severity::High, Severity::Warning],
        SeverityArg::Info => vec![Severity::High, Severity::Warning, Severity::Info],
    };

    let important: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| shown_severities.contains(&f.severity))
        .collect();

    if !important.is_empty() {
        eprintln!();
        eprintln!("  {}", "Findings:".bold());

        // Collect new finding IDs for [NEW] tag display
        let new_ids: std::collections::HashSet<String> = report
            .baseline_diff
            .as_ref()
            .map(|d| d.new_findings.iter().cloned().collect())
            .unwrap_or_default();

        for f in &important {
            let sev = match f.severity {
                Severity::High => "[HIGH]   ".red().bold(),
                Severity::Warning => "[WARN]   ".yellow(),
                Severity::Info => "[INFO]   ".white(),
                Severity::Secure => "[SECURE] ".green(),
            };
            let new_tag = if new_ids.contains(&f.id) {
                format!(" {}", "[NEW]".bright_cyan().bold())
            } else {
                String::new()
            };
            eprintln!("  {} {}{} ({})", sev, f.title, new_tag, f.id.dimmed());
            if let Some(ev) = f.evidence.first() {
                let truncated = truncate_str(ev, 80);
                eprintln!("           {}", truncated.dimmed());
            }
        }
    }

    if !report.secrets.is_empty() {
        eprintln!();
        eprintln!("  {}", "Secrets:".bold());
        for s in report.secrets.iter().take(10) {
            let sev = match s.severity {
                Severity::High => "[HIGH]".red().bold(),
                Severity::Warning => "[WARN]".yellow(),
                _ => "[INFO]".white(),
            };
            eprintln!("  {} {}", sev, s.title);
            let truncated = if s.matched_value.len() > 60 {
                format!("{}...", truncate_str(&s.matched_value, 60))
            } else {
                s.matched_value.clone()
            };
            eprintln!("         {}", truncated.dimmed());
        }
        if report.secrets.len() > 10 {
            eprintln!(
                "         {} {} more — use --format json for full report",
                "+".dimmed(),
                report.secrets.len() - 10
            );
        }
    }

    if let Some(bin) = &report.main_binary {
        eprintln!();
        eprintln!("  {} ({})", "Binary Protections:".bold(), bin.arch);
        for prot in &bin.protections {
            let icon = if prot.enabled {
                "✓".green()
            } else {
                "✗".red()
            };
            eprintln!("  {} {}", icon, prot.name);
        }
    }

    if !report.trackers.is_empty() {
        eprintln!();
        eprintln!("  {}", "Trackers Detected:".bold());
        for t in &report.trackers {
            eprintln!(
                "  • {} {}",
                t.name,
                format!("[{}]", t.categories.join(", ")).dimmed()
            );
        }
    }

    // Domain intelligence (only shown when --network was used)
    if !report.domain_intel.is_empty() {
        let ofac: Vec<_> = report
            .domain_intel
            .iter()
            .filter(|d| d.is_ofac_sanctioned)
            .collect();
        if !ofac.is_empty() {
            eprintln!();
            eprintln!("  {}", "OFAC-Sanctioned Servers:".red().bold());
            for d in &ofac {
                eprintln!(
                    "  {} {} → {} ({}, {})",
                    "⚠".red(),
                    d.domain,
                    d.ip.as_deref().unwrap_or("?"),
                    d.city.as_deref().unwrap_or("?"),
                    d.country.as_deref().unwrap_or("?")
                );
            }
        }

        eprintln!();
        eprintln!(
            "  {}  {} domains geolocated  │  {} OFAC matches",
            "Domain Intel:".bold(),
            report.domain_intel.len(),
            ofac.len()
        );
    }

    // Audit log (only shown with --verbose)
    if verbose && !report.scan_log.is_empty() {
        eprintln!();
        eprintln!("  {}", "Audit Log:".bold().dimmed());
        for entry in &report.scan_log {
            eprintln!(
                "  {}  {}",
                format!("{:>6}ms", entry.elapsed_ms).dimmed(),
                entry.step.dimmed()
            );
        }
    }

    eprintln!();
}

fn score_bar(score: u8) -> String {
    let filled = (score as usize / 10).min(10);
    let empty = 10 - filled;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}
