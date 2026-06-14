use serde::{Deserialize, Serialize};

/// Deep packet inspection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpiResult {
    Matched { protocol: &'static str, confidence: Confidence },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence { High, Medium }
