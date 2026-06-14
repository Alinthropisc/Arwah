//! Detection engine — Observer pattern, rules emit alerts.

use b579_core::{
    alert::{Alert, AlertCategory, Severity},
    packet::ParsedPacket,
    protocol::L4Protocol,
};
use chrono::Utc;
use dashmap::DashMap;
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
};
use tokio::sync::broadcast;

const CAP: usize = 512;

trait Rule: Send + Sync { fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert>; }

/// per-(src,dst) set of unique dst ports — vertical scan
type VerticalMap = DashMap<(IpAddr, IpAddr), HashSet<u16>>;
/// per-(src,port) set of unique dst IPs — horizontal scan
type HorizontalMap = DashMap<(IpAddr, u16), HashSet<IpAddr>>;

#[derive(Default)]
struct State {
    syn:        DashMap<IpAddr, u64>,
    icmp:       DashMap<IpAddr, u64>,
    vert_scan:  VerticalMap,
    horiz_scan: HorizontalMap,
}

pub struct AlertEngine {
    rules: Vec<Box<dyn Rule>>,
    state: Arc<State>,
    pub tx: broadcast::Sender<Alert>,
    seq: AtomicU64,
}

impl AlertEngine {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CAP);
        Self {
            rules: vec![
                Box::new(SynFlood      { threshold: 200 }),
                Box::new(IcmpFlood     { threshold: 500 }),
                Box::new(BadTtl),
                Box::new(SuspPort),
                Box::new(VerticalScan  { threshold: 20 }),
                Box::new(HorizontalScan{ threshold: 15 }),
            ],
            state: Arc::new(State::default()),
            tx, seq: AtomicU64::new(1),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Alert> { self.tx.subscribe() }

    pub fn inspect(&self, pkt: &ParsedPacket) {
        for rule in &self.rules {
            if let Some(mut a) = rule.check(pkt, &self.state) {
                a.id = self.seq.fetch_add(1, Ordering::Relaxed);
                let _ = self.tx.send(a);
            }
        }
    }

    pub fn reset(&self) {
        self.state.syn.clear();
        self.state.icmp.clear();
        self.state.vert_scan.clear();
        self.state.horiz_scan.clear();
    }
}

impl Default for AlertEngine { fn default() -> Self { Self::new() } }

fn alert(sev: Severity, cat: AlertCategory, msg: String, pkt: &ParsedPacket) -> Alert {
    Alert { id: 0, timestamp: Utc::now(), severity: sev, category: cat, message: msg,
            src_ip: pkt.src_ip, dst_ip: pkt.dst_ip,
            src_port: pkt.src_port, dst_port: pkt.dst_port }
}

struct SynFlood { threshold: u64 }
impl Rule for SynFlood {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        if pkt.l4 != Some(L4Protocol::Tcp) || !pkt.flags.is_connection_start() { return None; }
        let src = pkt.src_ip?;
        let mut c = s.syn.entry(src).or_insert(0); *c += 1;
        (*c == self.threshold).then(|| alert(Severity::High, AlertCategory::SynFlood,
            format!("SYN flood from {src}: {} SYNs", *c), pkt))
    }
}

struct IcmpFlood { threshold: u64 }
impl Rule for IcmpFlood {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        if pkt.l4 != Some(L4Protocol::Icmp) { return None; }
        let src = pkt.src_ip?;
        let mut c = s.icmp.entry(src).or_insert(0); *c += 1;
        (*c == self.threshold).then(|| alert(Severity::Medium, AlertCategory::IcmpFlood,
            format!("ICMP flood from {src}"), pkt))
    }
}

struct BadTtl;
impl Rule for BadTtl {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        (pkt.ttl.unwrap_or(128) <= 1 && pkt.l4 != Some(L4Protocol::Icmp)).then(||
            alert(Severity::Low, AlertCategory::AbnormalTtl,
                format!("TTL={}", pkt.ttl.unwrap_or(0)), pkt))
    }
}

struct SuspPort;
impl Rule for SuspPort {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        const BAD: &[u16] = &[4444, 31337, 1337, 6667, 9001, 9030, 14433];
        pkt.dst_port
            .filter(|p| BAD.contains(p))
            .map(|p| alert(Severity::Medium, AlertCategory::SuspiciousPort,
                format!("Suspicious port {p}"), pkt))
    }
}

/// Vertical scan: one src probes many ports on the same dst.
struct VerticalScan { threshold: usize }
impl Rule for VerticalScan {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        let src = pkt.src_ip?;
        let dst = pkt.dst_ip?;
        let port = pkt.dst_port?;
        let mut entry = s.vert_scan.entry((src, dst)).or_default();
        entry.insert(port);
        let count = entry.len();
        (count == self.threshold).then(|| alert(
            Severity::High, AlertCategory::PortScan,
            format!("Vertical port scan: {src} → {dst}, {count} ports"), pkt,
        ))
    }
}

/// Horizontal scan: one src probes the same port across many hosts.
struct HorizontalScan { threshold: usize }
impl Rule for HorizontalScan {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        let src  = pkt.src_ip?;
        let dst  = pkt.dst_ip?;
        let port = pkt.dst_port?;
        let mut entry = s.horiz_scan.entry((src, port)).or_default();
        entry.insert(dst);
        let count = entry.len();
        (count == self.threshold).then(|| alert(
            Severity::High, AlertCategory::PortScan,
            format!("Horizontal port scan: {src} port {port} → {count} hosts"), pkt,
        ))
    }
}
