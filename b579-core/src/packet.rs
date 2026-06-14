use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::protocol::{AppProtocol, L3Protocol, L4Protocol};

/// Raw captured packet with metadata.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Capture timestamp with microsecond precision.
    pub timestamp: DateTime<Utc>,
    /// Interface the packet was captured on.
    pub interface: String,
    /// Entire frame bytes (link-layer header included).
    pub data: Box<[u8]>,
}

/// Parsed, protocol-decoded packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub timestamp: DateTime<Utc>,
    pub interface: String,
    pub len: u32,

    pub l3: L3Protocol,
    pub l4: Option<L4Protocol>,
    pub app: AppProtocol,

    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,

    pub ttl: Option<u8>,
    pub flags: TcpFlags,

    pub payload_len: usize,
}

/// TCP control-bit flags extracted from the TCP header.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    #[inline]
    pub fn is_syn_only(self) -> bool {
        self.syn && !self.ack && !self.fin && !self.rst
    }

    #[inline]
    pub fn is_connection_start(self) -> bool {
        self.syn && !self.ack
    }
}
