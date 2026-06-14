use b579_core::{
    packet::ParsedPacket,
    protocol::L4Protocol,
    stats::{CaptureStats, TrafficSnapshot},
};
use chrono::Utc;
use parking_lot::RwLock;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

/// Rolling statistics aggregator.
///
/// Designed to be shared (`Arc<StatsEngine>`) across the capture task
/// and the TUI render loop with minimal contention.
#[derive(Debug)]
pub struct StatsEngine {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    total_packets: u64,
    total_bytes: u64,
    proto_dist: HashMap<L4Protocol, u64>,
    talker_bytes: HashMap<IpAddr, u64>,
}

impl StatsEngine {
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::default()) }
    }

    pub fn record(&self, pkt: &ParsedPacket) {
        let mut w = self.inner.write();
        w.total_packets += 1;
        w.total_bytes += pkt.len as u64;

        if let Some(l4) = pkt.l4 {
            *w.proto_dist.entry(l4).or_default() += 1;
        }
        if let Some(src) = pkt.src_ip {
            *w.talker_bytes.entry(src).or_default() += pkt.len as u64;
        }
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        let r = self.inner.read();
        let mut top: Vec<(IpAddr, u64)> = r.talker_bytes.iter().map(|(k, v)| (*k, *v)).collect();
        top.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10);

        TrafficSnapshot {
            captured_at: Some(Utc::now()),
            total_packets: r.total_packets,
            total_bytes: r.total_bytes,
            pps: 0.0,
            bps: 0.0,
            top_talkers: top,
            proto_dist: r.proto_dist.clone(),
            app_dist: HashMap::new(),
        }
    }
}

impl Default for StatsEngine {
    fn default() -> Self {
        Self::new()
    }
}
