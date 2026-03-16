use anyhow::Result;
use crate::types::ScanReport;

pub fn to_string(report: &ScanReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}
