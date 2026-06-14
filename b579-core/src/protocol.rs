use serde::{Deserialize, Serialize};

/// Layer-3 network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum L3Protocol {
    IPv4,
    IPv6,
    Arp,
    Other(u16),
}

/// Layer-4 transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Sctp,
    Other(u8),
}

/// Well-known application-layer protocol inferred from port or payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AppProtocol {
    Http,
    Https,
    Dns,
    Dhcp,
    Ssh,
    Ftp,
    Smtp,
    Imap,
    Pop3,
    Rdp,
    Smb,
    Ntp,
    Mdns,
    Quic,
    Unknown,
}

impl AppProtocol {
    /// Infer application protocol from destination port (best-effort).
    pub fn from_port(port: u16) -> Self {
        match port {
            80 | 8080 => Self::Http,
            443 | 8443 => Self::Https,
            53 => Self::Dns,
            67 | 68 => Self::Dhcp,
            22 => Self::Ssh,
            20 | 21 => Self::Ftp,
            25 | 587 | 465 => Self::Smtp,
            143 | 993 => Self::Imap,
            110 | 995 => Self::Pop3,
            3389 => Self::Rdp,
            445 | 139 => Self::Smb,
            123 => Self::Ntp,
            5353 => Self::Mdns,
            _ => Self::Unknown,
        }
    }
}
