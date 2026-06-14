//! IP and domain blacklist loaded from a flat text file.
//!
//! One entry per line. Lines starting with `#` are ignored.
//! Supports plain IPs (`1.2.3.4`), CIDR ranges (`10.0.0.0/8`),
//! and domain names (`malware.example.com`).

use b579_core::{alert::{Alert, AlertCategory, Severity}, packet::ParsedPacket};
use chrono::Utc;
use ipnet::IpNet;
use std::{collections::HashSet, fs, net::IpAddr, path::Path, str::FromStr};

#[derive(Default)]
pub struct Blacklist {
    ips:     HashSet<IpAddr>,
    nets:    Vec<IpNet>,
    domains: HashSet<String>,
}

impl Blacklist {
    pub fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut bl = Self::default();
        for line in fs::read_to_string(path)?.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Ok(ip) = IpAddr::from_str(line) {
                bl.ips.insert(ip);
            } else if let Ok(net) = IpNet::from_str(line) {
                bl.nets.push(net);
            } else {
                bl.domains.insert(line.to_ascii_lowercase());
            }
        }
        Ok(bl)
    }

    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|n| n.contains(&ip))
    }

    pub fn contains_domain(&self, domain: &str) -> bool {
        self.domains.contains(&domain.to_ascii_lowercase())
    }

    pub fn check_packet(&self, pkt: &ParsedPacket) -> Option<Alert> {
        let hit = pkt.src_ip.filter(|ip| self.contains_ip(*ip))
            .or_else(|| pkt.dst_ip.filter(|ip| self.contains_ip(*ip)))?;

        Some(Alert {
            id: 0,
            timestamp: Utc::now(),
            severity: Severity::Critical,
            category: AlertCategory::SuspiciousPort,
            message: format!("Blacklisted IP: {hit}"),
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bl_from_str(s: &str) -> Blacklist {
        let mut bl = Blacklist::default();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Ok(ip) = IpAddr::from_str(line)  { bl.ips.insert(ip); }
            else if let Ok(net) = IpNet::from_str(line) { bl.nets.push(net); }
            else { bl.domains.insert(line.to_ascii_lowercase()); }
        }
        bl
    }

    #[test]
    fn ip_hit() {
        let bl = bl_from_str("1.2.3.4\nexample.com");
        assert!(bl.contains_ip("1.2.3.4".parse().unwrap()));
        assert!(!bl.contains_ip("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn cidr_hit() {
        let bl = bl_from_str("10.0.0.0/8");
        assert!(bl.contains_ip("10.1.2.3".parse().unwrap()));
        assert!(!bl.contains_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn domain_hit() {
        let bl = bl_from_str("Malware.Example.COM");
        assert!(bl.contains_domain("malware.example.com"));
        assert!(!bl.contains_domain("safe.example.com"));
    }
}
