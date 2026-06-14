//! Rolling statistics — Decorator over raw counters + PPS/BPS sliding window.

use b579_core::{
    packet::ParsedPacket,
    protocol::{AppProtocol, L4Protocol},
    stats::TrafficSnapshot,
};
use chrono::Utc;
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::Instant,
};

/// One-second sliding window for PPS/BPS.
/// Keeps two buckets (current + previous); swaps when the second rolls over.
#[derive(Debug)]
struct RateTracker {
    cur_pkts:    u64,
    cur_bytes:   u64,
    prev_pkts:   u64,
    prev_bytes:  u64,
    window_start: Instant,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            cur_pkts: 0, cur_bytes: 0,
            prev_pkts: 0, prev_bytes: 0,
            window_start: Instant::now(),
        }
    }

    fn record(&mut self, bytes: u64) {
        if self.window_start.elapsed().as_secs() >= 1 {
            self.prev_pkts  = self.cur_pkts;
            self.prev_bytes = self.cur_bytes;
            self.cur_pkts   = 0;
            self.cur_bytes  = 0;
            self.window_start = Instant::now();
        }
        self.cur_pkts  += 1;
        self.cur_bytes += bytes;
    }

    /// Returns (pps, bps) based on the completed previous second.
    fn rates(&self) -> (f64, f64) {
        (self.prev_pkts as f64, self.prev_bytes as f64 * 8.0)
    }
}

impl Default for RateTracker {
    fn default() -> Self { Self::new() }
}

/// Rolling statistics aggregator.
///
/// Share as `Arc<StatsEngine>` across the capture task and TUI render loop.
#[derive(Debug)]
pub struct StatsEngine {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    total_packets:  u64,
    total_bytes:    u64,
    proto_pkts:     HashMap<L4Protocol,  u64>,
    proto_bytes:    HashMap<L4Protocol,  u64>,
    app_pkts:       HashMap<AppProtocol, u64>,
    app_bytes:      HashMap<AppProtocol, u64>,
    talker_bytes:   HashMap<IpAddr, u64>,
    talker_packets: HashMap<IpAddr, u64>,
    rate:           RateTracker,
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
        w.rate.record(bytes);

        if let Some(l4) = pkt.l4 {
            *w.proto_pkts .entry(l4).or_default() += 1;
            *w.proto_bytes.entry(l4).or_default() += bytes;
        }
        *w.app_pkts .entry(pkt.app).or_default() += 1;
        *w.app_bytes.entry(pkt.app).or_default() += bytes;

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

        let (pps, bps) = r.rate.rates();

        TrafficSnapshot {
            captured_at:   Some(Utc::now()),
            total_packets: r.total_packets,
            total_bytes:   r.total_bytes,
            pps,
            bps,
            top_talkers:   top,
            proto_dist:    r.proto_pkts.clone(),
            app_dist:      r.app_pkts.clone(),
        }
    }

    pub fn top_talkers(&self, n: usize) -> Vec<(IpAddr, u64)> {
        let r = self.inner.read();
        let mut v: Vec<(IpAddr, u64)> =
            r.talker_bytes.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn proto_byte_dist(&self) -> HashMap<L4Protocol,  u64> {
        self.inner.read().proto_bytes.clone()
    }

    pub fn app_byte_dist(&self) -> HashMap<AppProtocol, u64> {
        self.inner.read().app_bytes.clone()
    }
}

impl Default for StatsEngine {
    fn default() -> Self { Self::new() }
}
