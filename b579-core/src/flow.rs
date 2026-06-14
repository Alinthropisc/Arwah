use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::protocol::{AppProtocol, L4Protocol};

/// Five-tuple identifying a network flow (bidirectional).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: L4Protocol,
}

impl FlowKey {
    /// Returns the canonical key where src < dst (for bidirectional matching).
    pub fn canonical(self) -> Self {
        let a = (self.src_ip, self.src_port);
        let b = (self.dst_ip, self.dst_port);
        if a <= b {
            self
        } else {
            FlowKey {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}

/// Current lifecycle state of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    New,
    Established,
    Closing,
    Closed,
}

/// Aggregated statistics for a single network flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub app_protocol: AppProtocol,
    pub state: FlowState,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
}

impl FlowRecord {
    pub fn total_packets(&self) -> u64 {
        self.packets_fwd + self.packets_rev
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_fwd + self.bytes_rev
    }

    pub fn duration_ms(&self) -> i64 {
        (self.last_seen - self.first_seen).num_milliseconds()
    }
}
