//! Detection engine — Observer pattern, rules emit alerts.
//!
//! Two rule traits (Strategy):
//! - `Rule`     — fired per packet  (`AlertEngine::inspect`)
//! - `FlowRule` — fired per flow    (`AlertEngine::inspect_flow`)

use b579_core::{
    alert::{Alert, AlertCategory, Severity},
    flow::FlowRecord,
    packet::ParsedPacket,
    protocol::{AppProtocol, L4Protocol},
};
use chrono::Utc;
use dashmap::DashMap;
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::broadcast;

const CAP: usize = 512;

/// Observer: per-packet rule.
trait Rule: Send + Sync {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert>;
}

/// Strategy: per-flow rule — checked when a flow is evicted or finalised.
trait FlowRule: Send + Sync {
    fn check_flow(&self, flow: &FlowRecord) -> Option<Alert>;
}

type VerticalMap = DashMap<(IpAddr, IpAddr), HashSet<u16>>;
type HorizontalMap = DashMap<(IpAddr, u16), HashSet<IpAddr>>;

#[derive(Default)]
struct State {
    syn: DashMap<IpAddr, u64>,
    icmp: DashMap<IpAddr, u64>,
    vert_scan: VerticalMap,
    horiz_scan: HorizontalMap,
}

pub struct AlertEngine {
    rules: Vec<Box<dyn Rule>>,
    flow_rules: Vec<Box<dyn FlowRule>>,
    state: Arc<State>,
    pub tx: broadcast::Sender<Alert>,
    seq: AtomicU64,
}

impl AlertEngine {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CAP);
        Self {
            rules: vec![
                Box::new(SynFlood { threshold: 200 }),
                Box::new(IcmpFlood { threshold: 500 }),
                Box::new(BadTtl),
                Box::new(SuspPort),
                Box::new(VerticalScan { threshold: 20 }),
                Box::new(HorizontalScan { threshold: 15 }),
                Box::new(DnsExfil { max_payload: 80 }),
                Box::new(TlsNoSni),
            ],
            flow_rules: vec![
                Box::new(LargeTransfer {
                    threshold_bytes: 100 * 1024 * 1024,
                }), // 100 MB
            ],
            state: Arc::new(State::default()),
            tx,
            seq: AtomicU64::new(1),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Alert> {
        self.tx.subscribe()
    }

    /// Evaluate all per-packet rules.
    pub fn inspect(&self, pkt: &ParsedPacket) {
        for rule in &self.rules {
            if let Some(mut a) = rule.check(pkt, &self.state) {
                a.id = self.seq.fetch_add(1, Ordering::Relaxed);
                let _ = self.tx.send(a);
            }
        }
    }

    /// Evaluate all per-flow rules. Call when a flow is evicted or closed.
    pub fn inspect_flow(&self, flow: &FlowRecord) {
        for rule in &self.flow_rules {
            if let Some(mut a) = rule.check_flow(flow) {
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

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn alert(sev: Severity, cat: AlertCategory, msg: String, pkt: &ParsedPacket) -> Alert {
    Alert {
        id: 0,
        timestamp: Utc::now(),
        severity: sev,
        category: cat,
        message: msg,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
    }
}

fn flow_alert(sev: Severity, cat: AlertCategory, msg: String, flow: &FlowRecord) -> Alert {
    Alert {
        id: 0,
        timestamp: Utc::now(),
        severity: sev,
        category: cat,
        message: msg,
        src_ip: Some(flow.key.src_ip),
        dst_ip: Some(flow.key.dst_ip),
        src_port: Some(flow.key.src_port),
        dst_port: Some(flow.key.dst_port),
    }
}

// ── per-packet rules ─────────────────────────────────────────────────────────

struct SynFlood {
    threshold: u64,
}
impl Rule for SynFlood {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        if pkt.l4 != Some(L4Protocol::Tcp) || !pkt.flags.is_connection_start() {
            return None;
        }
        let src = pkt.src_ip?;
        let mut c = s.syn.entry(src).or_insert(0);
        *c += 1;
        (*c == self.threshold).then(|| {
            alert(
                Severity::High,
                AlertCategory::SynFlood,
                format!("SYN flood from {src}: {} SYNs", *c),
                pkt,
            )
        })
    }
}

struct IcmpFlood {
    threshold: u64,
}
impl Rule for IcmpFlood {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        if pkt.l4 != Some(L4Protocol::Icmp) {
            return None;
        }
        let src = pkt.src_ip?;
        let mut c = s.icmp.entry(src).or_insert(0);
        *c += 1;
        (*c == self.threshold).then(|| {
            alert(
                Severity::Medium,
                AlertCategory::IcmpFlood,
                format!("ICMP flood from {src}"),
                pkt,
            )
        })
    }
}

struct BadTtl;
impl Rule for BadTtl {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        (pkt.ttl.unwrap_or(128) <= 1 && pkt.l4 != Some(L4Protocol::Icmp)).then(|| {
            alert(
                Severity::Low,
                AlertCategory::AbnormalTtl,
                format!("TTL={}", pkt.ttl.unwrap_or(0)),
                pkt,
            )
        })
    }
}

struct SuspPort;
impl Rule for SuspPort {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        const BAD: &[u16] = &[4444, 31337, 1337, 6667, 9001, 9030, 14433];
        pkt.dst_port.filter(|p| BAD.contains(p)).map(|p| {
            alert(
                Severity::Medium,
                AlertCategory::SuspiciousPort,
                format!("Suspicious port {p}"),
                pkt,
            )
        })
    }
}

struct VerticalScan {
    threshold: usize,
}
impl Rule for VerticalScan {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        let src = pkt.src_ip?;
        let dst = pkt.dst_ip?;
        let port = pkt.dst_port?;
        let mut entry = s.vert_scan.entry((src, dst)).or_default();
        entry.insert(port);
        let count = entry.len();
        (count == self.threshold).then(|| {
            alert(
                Severity::High,
                AlertCategory::PortScan,
                format!("Vertical port scan: {src} → {dst}, {count} ports"),
                pkt,
            )
        })
    }
}

struct HorizontalScan {
    threshold: usize,
}
impl Rule for HorizontalScan {
    fn check(&self, pkt: &ParsedPacket, s: &State) -> Option<Alert> {
        let src = pkt.src_ip?;
        let dst = pkt.dst_ip?;
        let port = pkt.dst_port?;
        let mut entry = s.horiz_scan.entry((src, port)).or_default();
        entry.insert(dst);
        let count = entry.len();
        (count == self.threshold).then(|| {
            alert(
                Severity::High,
                AlertCategory::PortScan,
                format!("Horizontal port scan: {src} port {port} → {count} hosts"),
                pkt,
            )
        })
    }
}

/// DNS exfiltration heuristic: unusually large DNS query payload.
/// Normal DNS queries are < 60 bytes; data-exfil queries are typically > 80.
struct DnsExfil {
    max_payload: usize,
}
impl Rule for DnsExfil {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        if pkt.app != AppProtocol::Dns {
            return None;
        }
        if pkt.l4 != Some(L4Protocol::Udp) {
            return None;
        }
        (pkt.payload_len > self.max_payload).then(|| {
            alert(
                Severity::High,
                AlertCategory::DnsExfiltration,
                format!(
                    "DNS exfiltration: payload {} bytes (threshold {})",
                    pkt.payload_len, self.max_payload
                ),
                pkt,
            )
        })
    }
}

/// TLS anomaly: traffic on port 443/8443 that DPI did NOT classify as HTTPS.
/// This catches non-TLS tunnels (raw TCP, custom protos) abusing the HTTPS port.
struct TlsNoSni;
impl Rule for TlsNoSni {
    fn check(&self, pkt: &ParsedPacket, _: &State) -> Option<Alert> {
        let port = pkt.dst_port?;
        if port != 443 && port != 8443 {
            return None;
        }
        if pkt.l4 != Some(L4Protocol::Tcp) {
            return None;
        }
        // App protocol not resolved as HTTPS despite going to 443 → anomaly
        (pkt.app != AppProtocol::Https && pkt.app != AppProtocol::Unknown).then(|| {
            alert(
                Severity::Medium,
                AlertCategory::TlsAnomalyNoSni,
                format!("TLS port {port} carrying {:?} — possible tunnel", pkt.app),
                pkt,
            )
        })
    }
}

// ── per-flow rules ────────────────────────────────────────────────────────────

/// Alert when a single flow transfers more than `threshold_bytes` total.
struct LargeTransfer {
    threshold_bytes: u64,
}
impl FlowRule for LargeTransfer {
    fn check_flow(&self, flow: &FlowRecord) -> Option<Alert> {
        let total = flow.total_bytes();
        (total >= self.threshold_bytes).then(|| {
            flow_alert(
                Severity::Medium,
                AlertCategory::LargeTransfer,
                format!(
                    "Large transfer: {} MB in flow {}:{} → {}:{}",
                    total / (1024 * 1024),
                    flow.key.src_ip,
                    flow.key.src_port,
                    flow.key.dst_ip,
                    flow.key.dst_port
                ),
                flow,
            )
        })
    }
}
