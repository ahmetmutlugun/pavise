fn main() {
    let data = std::fs::read_to_string("scan_report.json").unwrap();
    let report: pavise::types::ScanReport = serde_json::from_str(&data).unwrap();
    let bytes = pavise::report::pdf::to_bytes(&report).unwrap();
    std::fs::write("/tmp/test_report.pdf", &bytes).unwrap();
    println!("PDF written ({} bytes) → /tmp/test_report.pdf", bytes.len());
}
