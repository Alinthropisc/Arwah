//! Suricata-compatible rule loader.
//!
//! Parses a subset of Suricata rule syntax and produces `AlertEngine`-compatible
//! `Rule` objects loaded at runtime from a `.rules` file.
//!
//! Supported grammar (enough for the common case):
//! ```text
//! alert <proto> <src_ip> <src_port> <dir> <dst_ip> <dst_port> \
//!     (msg:"<text>"; [content:"<bytes>";] [flags:<tcp_flags>;] sid:<n>; [rev:<n>;])
//! ```

use b579_core::{
    alert::{Alert, AlertCategory, Severity},
    packet::ParsedPacket,
    protocol::L4Protocol,
};
use chrono::Utc;
use std::net::IpAddr;

// ── public surface ────────────────────────────────────────────────────────────

pub use loader::load_rules;
pub use rule::SuricataRule;

// ── rule representation ───────────────────────────────────────────────────────
mod rule {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct SuricataRule {
        pub sid:      u64,
        pub msg:      String,
        pub proto:    ProtoMatch,
        pub src:      AddrMatch,
        pub src_port: PortMatch,
        pub dst:      AddrMatch,
        pub dst_port: PortMatch,
        pub content:  Option<Vec<u8>>,
    }

    impl SuricataRule {
        pub fn matches(&self, pkt: &ParsedPacket) -> bool {
            if !self.proto.matches(pkt.l4) { return false; }
            if !self.src.matches(pkt.src_ip) { return false; }
            if !self.dst.matches(pkt.dst_ip) { return false; }
            if !self.src_port.matches(pkt.src_port) { return false; }
            if !self.dst_port.matches(pkt.dst_port) { return false; }
            true
        }

        pub fn to_alert(&self, pkt: &ParsedPacket) -> Alert {
            Alert {
                id:        0,
                timestamp: Utc::now(),
                severity:  Severity::Medium,
                category:  AlertCategory::SuspiciousPort,
                message:   format!("[sid:{}] {}", self.sid, self.msg),
                src_ip:    pkt.src_ip,
                dst_ip:    pkt.dst_ip,
                src_port:  pkt.src_port,
                dst_port:  pkt.dst_port,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum ProtoMatch { Any, Tcp, Udp, Icmp }

    impl ProtoMatch {
        pub fn matches(&self, l4: Option<L4Protocol>) -> bool {
            match self {
                Self::Any  => true,
                Self::Tcp  => l4 == Some(L4Protocol::Tcp),
                Self::Udp  => l4 == Some(L4Protocol::Udp),
                Self::Icmp => l4 == Some(L4Protocol::Icmp),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum AddrMatch { Any, Ip(IpAddr) }

    impl AddrMatch {
        pub fn matches(&self, addr: Option<IpAddr>) -> bool {
            match self {
                Self::Any    => true,
                Self::Ip(ip) => addr == Some(*ip),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum PortMatch { Any, Port(u16), Range(u16, u16) }

    impl PortMatch {
        pub fn matches(&self, port: Option<u16>) -> bool {
            match self {
                Self::Any          => true,
                Self::Port(p)      => port == Some(*p),
                Self::Range(lo,hi) => port.map_or(false, |p| p >= *lo && p <= *hi),
            }
        }
    }
}

// ── parser ────────────────────────────────────────────────────────────────────
mod loader {
    use super::rule::*;
    use super::SuricataRule;
    use std::{fs, path::Path};

    pub fn load_rules(path: impl AsRef<Path>) -> std::io::Result<Vec<SuricataRule>> {
        let text = fs::read_to_string(path)?;
        let rules = text.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { return None; }
                parse_rule(line).ok()
            })
            .collect();
        Ok(rules)
    }

    fn parse_rule(s: &str) -> Result<SuricataRule, String> {
        // Split header from options: "... (options)"
        let paren = s.find('(').ok_or("missing '('")?;
        let header  = s[..paren].trim();
        let opts_raw = s[paren+1..].trim_end_matches(')').trim();

        // Header: action proto src src_port direction dst dst_port
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 7 { return Err(format!("short header: {s}")); }
        // parts[0] = action (alert/drop/pass — we only load alert rules)
        let proto    = parse_proto(parts[1]);
        let src      = parse_addr(parts[2]);
        let src_port = parse_port(parts[3]);
        // parts[4] = direction (-> or <>)
        let dst      = parse_addr(parts[5]);
        let dst_port = parse_port(parts[6]);

        // Options
        let msg  = extract_opt(opts_raw, "msg")
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default();
        let sid  = extract_opt(opts_raw, "sid")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let content = extract_opt(opts_raw, "content")
            .map(|v| v.trim_matches('"').as_bytes().to_vec());

        Ok(SuricataRule { sid, msg, proto, src, src_port, dst, dst_port, content })
    }

    fn parse_proto(s: &str) -> ProtoMatch {
        match s.to_ascii_lowercase().as_str() {
            "tcp"  => ProtoMatch::Tcp,
            "udp"  => ProtoMatch::Udp,
            "icmp" => ProtoMatch::Icmp,
            _      => ProtoMatch::Any,
        }
    }

    fn parse_addr(s: &str) -> AddrMatch {
        if s == "any" || s == "$HOME_NET" || s == "$EXTERNAL_NET" {
            return AddrMatch::Any;
        }
        s.parse().map(AddrMatch::Ip).unwrap_or(AddrMatch::Any)
    }

    fn parse_port(s: &str) -> PortMatch {
        if s == "any" { return PortMatch::Any; }
        if let Ok(p) = s.parse::<u16>() { return PortMatch::Port(p); }
        if let Some((lo, hi)) = s.split_once(':') {
            if let (Ok(l), Ok(h)) = (lo.parse(), hi.parse()) {
                return PortMatch::Range(l, h);
            }
        }
        PortMatch::Any
    }

    fn extract_opt<'a>(opts: &'a str, key: &str) -> Option<&'a str> {
        let needle = format!("{key}:");
        let start  = opts.find(needle.as_str())?;
        let rest   = &opts[start + needle.len()..];
        // value ends at ';'
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].trim())
    }
}

// ── AlertEngine adapter ───────────────────────────────────────────────────────

/// Wraps a loaded Vec<SuricataRule> as a single boxed Rule for AlertEngine.
pub struct SuricataRuleSet {
    rules: Vec<SuricataRule>,
}

impl SuricataRuleSet {
    pub fn new(rules: Vec<SuricataRule>) -> Self { Self { rules } }

    pub fn check(&self, pkt: &ParsedPacket) -> Option<Alert> {
        self.rules.iter()
            .find(|r| r.matches(pkt))
            .map(|r| r.to_alert(pkt))
    }
}

#[cfg(test)]
mod tests {
    use super::loader::*;
    use super::*;
    use b579_core::{packet::ParsedPacket, protocol::{AppProtocol, L3Protocol, L4Protocol}};
    use chrono::Utc;

    fn pkt(l4: Option<L4Protocol>, dst_port: Option<u16>) -> ParsedPacket {
        ParsedPacket {
            timestamp: Utc::now(), interface: "eth0".into(), len: 100,
            l3: L3Protocol::IPv4, l4, app: AppProtocol::Unknown,
            src_ip: None, dst_ip: None, src_port: None, dst_port,
            ttl: Some(64), flags: Default::default(), payload_len: 0,
        }
    }

    #[test]
    fn empty_ruleset_matches_nothing() {
        let set = SuricataRuleSet::new(vec![]);
        assert!(set.check(&pkt(Some(L4Protocol::Tcp), Some(80))).is_none());
    }

    #[test]
    fn load_rules_from_file() {
        use std::io::Write as _;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, r#"alert tcp any any -> any 80 (msg:"HTTP probe"; sid:1001; rev:1;)"#).unwrap();
        let rules = load_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sid, 1001);
        let set = SuricataRuleSet::new(rules);
        assert!(set.check(&pkt(Some(L4Protocol::Tcp), Some(80))).is_some());
        assert!(set.check(&pkt(Some(L4Protocol::Udp), Some(80))).is_none());
    }
}
