//! Deep Packet Inspection — payload-based protocol fingerprinting.
//! Chain of Responsibility pattern.

use b579_core::{dpi::{Confidence, DpiResult}, packet::ParsedPacket};

trait Detector: Send + Sync {
    fn probe(&self, payload: &[u8], pkt: &ParsedPacket) -> Option<DpiResult>;
}

pub struct DpiEngine { detectors: Vec<Box<dyn Detector>> }

impl DpiEngine {
    pub fn default_set() -> Self {
        Self { detectors: vec![
            Box::new(HttpDetector), Box::new(TlsDetector), Box::new(DnsDetector),
            Box::new(SshDetector),  Box::new(QuicDetector), Box::new(WireGuardDetector),
        ]}
    }

    pub fn inspect(&self, payload: &[u8], pkt: &ParsedPacket) -> DpiResult {
        for d in &self.detectors { if let Some(r) = d.probe(payload, pkt) { return r; } }
        DpiResult::Unknown
    }
}

impl Default for DpiEngine { fn default() -> Self { Self::default_set() } }

macro_rules! pattern_detector {
    ($name:ident, $proto:literal, $($magic:expr),+) => {
        struct $name;
        impl Detector for $name {
            fn probe(&self, payload: &[u8], _: &ParsedPacket) -> Option<DpiResult> {
                if $( payload.starts_with($magic) )||+ {
                    Some(DpiResult::Matched { protocol: $proto, confidence: Confidence::High })
                } else { None }
            }
        }
    };
}

pattern_detector!(HttpDetector, "HTTP",  b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/");
pattern_detector!(SshDetector,  "SSH",   b"SSH-");

struct TlsDetector;
impl Detector for TlsDetector {
    fn probe(&self, payload: &[u8], _: &ParsedPacket) -> Option<DpiResult> {
        if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
            Some(DpiResult::Matched { protocol: "TLS", confidence: Confidence::High })
        } else { None }
    }
}

struct DnsDetector;
impl Detector for DnsDetector {
    fn probe(&self, payload: &[u8], pkt: &ParsedPacket) -> Option<DpiResult> {
        if payload.len() >= 12 && (pkt.src_port == Some(53) || pkt.dst_port == Some(53)) {
            Some(DpiResult::Matched { protocol: "DNS", confidence: Confidence::Medium })
        } else { None }
    }
}

struct QuicDetector;
impl Detector for QuicDetector {
    fn probe(&self, payload: &[u8], _: &ParsedPacket) -> Option<DpiResult> {
        if payload.len() >= 5 && (payload[0] & 0xC0) == 0xC0 {
            let ver = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            if ver == 1 || (ver >> 8) == 0xff0000 {
                return Some(DpiResult::Matched { protocol: "QUIC", confidence: Confidence::High });
            }
        }
        None
    }
}

struct WireGuardDetector;
impl Detector for WireGuardDetector {
    fn probe(&self, payload: &[u8], pkt: &ParsedPacket) -> Option<DpiResult> {
        if payload.len() >= 4 && payload[..4] == [1, 0, 0, 0]
            && (pkt.dst_port == Some(51820) || pkt.src_port == Some(51820))
        {
            Some(DpiResult::Matched { protocol: "WireGuard", confidence: Confidence::Medium })
        } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use b579_core::{packet::ParsedPacket, protocol::{AppProtocol, L3Protocol}};
    use chrono::Utc;

    fn bare_pkt() -> ParsedPacket {
        ParsedPacket {
            timestamp: Utc::now(), interface: "eth0".into(), len: 0,
            l3: L3Protocol::IPv4, l4: None, app: AppProtocol::Unknown,
            src_ip: None, dst_ip: None, src_port: None, dst_port: None,
            ttl: None, flags: Default::default(), payload_len: 0,
        }
    }

    #[test]
    fn detects_http() {
        let r = DpiEngine::default_set().inspect(b"GET / HTTP/1.1\r\n", &bare_pkt());
        assert!(matches!(r, DpiResult::Matched { protocol: "HTTP", .. }));
    }

    #[test]
    fn detects_tls() {
        let r = DpiEngine::default_set().inspect(&[0x16, 0x03, 0x03, 0, 0], &bare_pkt());
        assert!(matches!(r, DpiResult::Matched { protocol: "TLS", .. }));
    }

    #[test]
    fn unknown_stays_unknown() {
        let r = DpiEngine::default_set().inspect(b"\x00\x00\x00", &bare_pkt());
        assert_eq!(r, DpiResult::Unknown);
    }
}
