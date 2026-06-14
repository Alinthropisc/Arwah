use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::protocol::{AppProtocol, L4Protocol};

/// Rolling traffic statistics snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub captured_at: Option<DateTime<Utc>>,

    pub total_packets: u64,
    pub total_bytes: u64,

    /// Packets/bytes in the last second window.
    pub pps: f64,
    pub bps: f64,

    pub top_talkers: Vec<(IpAddr, u64)>,
    pub proto_dist: HashMap<L4Protocol, u64>,
    pub app_dist: HashMap<AppProtocol, u64>,
}

/// Interface-level capture statistics returned from the kernel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub received: u64,
    pub dropped_kernel: u64,
    pub dropped_iface: u64,
}

impl CaptureStats {
    pub fn drop_ratio(&self) -> f64 {
        if self.received == 0 {
            0.0
        } else {
            self.dropped_kernel as f64 / self.received as f64
        }
    }
}
