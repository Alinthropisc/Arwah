//! Suricata-compatible EVE JSON output.

use b579_core::{
    alert::{Alert, AlertCategory, Severity},
    flow::{FlowRecord, FlowState},
    protocol::L4Protocol,
};
use serde::Serialize;
use std::{net::IpAddr, path::Path};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

fn proto_str(proto: L4Protocol) -> &'static str {
    match proto {
        L4Protocol::Tcp   => "TCP",
        L4Protocol::Udp   => "UDP",
        L4Protocol::Icmp  => "ICMP",
        L4Protocol::IcmpV6 => "IPv6-ICMP",
        L4Protocol::Sctp  => "SCTP",
        L4Protocol::Other(_) => "unknown",
        _ => "unknown",
    }
}

fn severity_num(s: Severity) -> u8 {
    match s {
        Severity::Info     => 5,
        Severity::Low      => 4,
        Severity::Medium   => 3,
        Severity::High     => 2,
        Severity::Critical => 1,
    }
}

fn flow_state_str(s: FlowState) -> &'static str {
    match s {
        FlowState::New         => "new",
        FlowState::Established => "established",
        FlowState::Closing     => "closing",
        FlowState::Closed      => "closed",
    }
}

fn category_str(c: AlertCategory) -> &'static str {
    match c {
        AlertCategory::PortScan          => "Attempted Information Leak",
        AlertCategory::SynFlood          => "Denial of Service Attack",
        AlertCategory::LargeTransfer     => "Potentially Bad Traffic",
        AlertCategory::DnsExfiltration   => "DNS Exfiltration",
        AlertCategory::TlsAnomalyNoSni   => "TLS Anomaly",
        AlertCategory::SuspiciousPort    => "Misc activity",
        AlertCategory::IcmpFlood         => "Denial of Service Attack",
        AlertCategory::AbnormalTtl       => "Potentially Bad Traffic",
    }
}

/// Async EVE JSON writer — appends newline-delimited JSON to a file.
pub struct EveWriter {
    path: std::path::PathBuf,
}

impl EveWriter {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    async fn append(&self, line: String) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        Ok(())
    }

    pub async fn write_alert(&self, a: &Alert) -> std::io::Result<()> {
        #[derive(Serialize)]
        struct AlertField<'a> {
            action:       &'static str,
            gid:          u32,
            signature_id: u64,
            rev:          u32,
            signature:    &'a str,
            category:     &'static str,
            severity:     u8,
        }
        #[derive(Serialize)]
        struct Eve<'a> {
            timestamp:  String,
            event_type: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            src_ip:     Option<IpAddr>,
            #[serde(skip_serializing_if = "Option::is_none")]
            src_port:   Option<u16>,
            #[serde(skip_serializing_if = "Option::is_none")]
            dest_ip:    Option<IpAddr>,
            #[serde(skip_serializing_if = "Option::is_none")]
            dest_port:  Option<u16>,
            alert:      AlertField<'a>,
        }
        let ev = Eve {
            timestamp:  a.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            event_type: "alert",
            src_ip:     a.src_ip,
            src_port:   a.src_port,
            dest_ip:    a.dst_ip,
            dest_port:  a.dst_port,
            alert: AlertField {
                action:       "allowed",
                gid:          1,
                signature_id: a.id,
                rev:          1,
                signature:    &a.message,
                category:     category_str(a.category),
                severity:     severity_num(a.severity),
            },
        };
        self.append(serde_json::to_string(&ev)?).await
    }

    pub async fn write_flow(&self, f: &FlowRecord) -> std::io::Result<()> {
        #[derive(Serialize)]
        struct FlowField {
            pkts_toserver:  u64,
            pkts_toclient:  u64,
            bytes_toserver: u64,
            bytes_toclient: u64,
            start:          String,
            end:            String,
            state:          &'static str,
        }
        #[derive(Serialize)]
        struct Eve {
            timestamp:  String,
            event_type: &'static str,
            src_ip:     IpAddr,
            src_port:   u16,
            dest_ip:    IpAddr,
            dest_port:  u16,
            proto:      &'static str,
            flow:       FlowField,
        }
        let ev = Eve {
            timestamp:  f.last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            event_type: "flow",
            src_ip:     f.key.src_ip,
            src_port:   f.key.src_port,
            dest_ip:    f.key.dst_ip,
            dest_port:  f.key.dst_port,
            proto:      proto_str(f.key.protocol),
            flow: FlowField {
                pkts_toserver:  f.packets_fwd,
                pkts_toclient:  f.packets_rev,
                bytes_toserver: f.bytes_fwd,
                bytes_toclient: f.bytes_rev,
                start: f.first_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                end:   f.last_seen.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                state: flow_state_str(f.state),
            },
        };
        self.append(serde_json::to_string(&ev)?).await
    }
}
