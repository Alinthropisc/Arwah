//! Rolling statistics — Decorator over raw counters.
//!
//! `StatsEngine::record` acts as a Decorator: it receives a `ParsedPacket`
//! and enriches multiple independent counters (total, per-L4, per-App,
//! per-IP talker) without any caller needing to know which counters exist.

use b579_core::{
    packet::ParsedPacket,
    protocol::{AppProtocol, L4Protocol},
    stats::{CaptureStats, TrafficSnapshot},
};
use chrono::Utc;
use parking_lot::RwLock;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

/// Rolling statistics aggregator.
///
/// Share as `Arc<StatsEngine>` across the capture task and TUI render loop.
#[derive(Debug)]
pub struct StatsEngine {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    total_packets:   u64,
    total_bytes:     u64,
    /// packets per L4 protocol
    proto_pkts:      HashMap<L4Protocol, u64>,
    /// bytes per L4 protocol
    proto_bytes:     HashMap<L4Protocol, u64>,
    /// packets per App protocol
    app_pkts:        HashMap<AppProtocol, u64>,
    /// bytes per App protocol
    app_bytes:       HashMap<AppProtocol, u64>,
    /// total bytes sent OR received per IP (both directions tracked)
    talker_bytes:    HashMap<IpAddr, u64>,
    talker_packets:  HashMap<IpAddr, u64>,
}

impl StatsEngine {
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::default()) }
    }

    pub fn record(&self, pkt: &ParsedPacket) {
        let mut w = self.inner.write();
        let bytes = pkt.len as u64;

        w.total_packets += 1;
        w.total_bytes   += bytes;

        if let Some(l4) = pkt.l4 {
            *w.proto_pkts .entry(l4).or_default() += 1;
            *w.proto_bytes.entry(l4).or_default() += bytes;
        }

        *w.app_pkts .entry(pkt.app).or_default() += 1;
        *w.app_bytes.entry(pkt.app).or_default() += bytes;

        // Count bytes for both src and dst so top-talkers reflects total activity
        if let Some(ip) = pkt.src_ip {
            *w.talker_bytes  .entry(ip).or_default() += bytes;
            *w.talker_packets.entry(ip).or_default() += 1;
        }
        if let Some(ip) = pkt.dst_ip {
            *w.talker_bytes  .entry(ip).or_default() += bytes;
            *w.talker_packets.entry(ip).or_default() += 1;
        }
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        let r = self.inner.read();

        let mut top: Vec<(IpAddr, u64)> =
            r.talker_bytes.iter().map(|(k, v)| (*k, *v)).collect();
        top.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10);

        // proto_dist in the snapshot keeps packet counts (backwards-compat)
        let proto_dist = r.proto_pkts.clone();
        // app_dist: packet counts per AppProtocol
        let app_dist = r.app_pkts.clone();

        TrafficSnapshot {
            captured_at:   Some(Utc::now()),
            total_packets: r.total_packets,
            total_bytes:   r.total_bytes,
            pps:           0.0,
            bps:           0.0,
            top_talkers:   top,
            proto_dist,
            app_dist,
        }
    }

    /// Top N IPs by total bytes (both src + dst counted).
    pub fn top_talkers(&self, n: usize) -> Vec<(IpAddr, u64)> {
        let r = self.inner.read();
        let mut v: Vec<(IpAddr, u64)> =
            r.talker_bytes.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Per-L4 protocol byte distribution (for TUI pie / table).
    pub fn proto_byte_dist(&self) -> HashMap<L4Protocol, u64> {
        self.inner.read().proto_bytes.clone()
    }

    /// Per-App protocol byte distribution.
    pub fn app_byte_dist(&self) -> HashMap<AppProtocol, u64> {
        self.inner.read().app_bytes.clone()
    }
}

impl Default for StatsEngine {
    fn default() -> Self { Self::new() }
}
