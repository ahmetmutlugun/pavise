use crate::types::ScanReport;
use anyhow::Result;

pub fn to_string(report: &ScanReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}
