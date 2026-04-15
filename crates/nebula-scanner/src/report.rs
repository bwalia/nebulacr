//! Report generation. JSON is just `serde_json::to_string(&ScanResult)`; the
//! HTML report lives in a later slice.

use crate::model::ScanResult;
use crate::Result;

pub fn to_json(result: &ScanResult) -> Result<String> {
    Ok(serde_json::to_string_pretty(result)?)
}
