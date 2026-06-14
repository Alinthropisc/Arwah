use b579_core::{
    error::{ArwahError, ArwahResult},
    packet::{ParsedPacket, RawPacket, TcpFlags},
    protocol::{AppProtocol, L3Protocol, L4Protocol},
};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Stateless packet decoder backed by the `etherparse` library.
///
/// Zero-copy slice-based parsing — no heap allocation for the packet payload.
#[derive(Debug, Default)]
pub struct EtherparseDecoder;

impl EtherparseDecoder {
    pub fn decode(&self, raw: &RawPacket) -> ArwahResult<ParsedPacket> {
        let headers = SlicedPacket::from_ethernet(&raw.data)
            .map_err(|e| ArwahError::Dissection(e.to_string()))?;

        let (l3, src_ip, dst_ip, ttl) = match &headers.net {
            Some(NetSlice::Ipv4(ip)) => {
                let h = ip.header();
                (
                    L3Protocol::IPv4,
                    Some(std::net::IpAddr::V4(h.source_addr())),
                    Some(std::net::IpAddr::V4(h.destination_addr())),
                    Some(h.ttl()),
                )
            }
            Some(NetSlice::Ipv6(ip)) => {
                let h = ip.header();
                (
                    L3Protocol::IPv6,
                    Some(std::net::IpAddr::V6(h.source_addr())),
                    Some(std::net::IpAddr::V6(h.destination_addr())),
                    None,
                )
            }
            _ => (L3Protocol::Other(0), None, None, None),
        };

        let (l4, src_port, dst_port, flags) = match &headers.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let h = tcp.to_header();
                let fl = TcpFlags {
                    syn: h.syn,
                    ack: h.ack,
                    fin: h.fin,
                    rst: h.rst,
                    psh: h.psh,
                    urg: h.urg,
                };
                (
                    Some(L4Protocol::Tcp),
                    Some(h.source_port),
                    Some(h.destination_port),
                    fl,
                )
            }
            Some(TransportSlice::Udp(udp)) => {
                let h = udp.to_header();
                (
                    Some(L4Protocol::Udp),
                    Some(h.source_port),
                    Some(h.destination_port),
                    TcpFlags::default(),
                )
            }
            Some(TransportSlice::Icmpv4(_)) => {
                (Some(L4Protocol::Icmp), None, None, TcpFlags::default())
            }
            Some(TransportSlice::Icmpv6(_)) => {
                (Some(L4Protocol::IcmpV6), None, None, TcpFlags::default())
            }
            _ => (None, None, None, TcpFlags::default()),
        };

        let app = dst_port
            .map(AppProtocol::from_port)
            .unwrap_or(AppProtocol::Unknown);

        let payload_len = match &headers.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp.payload().len(),
            Some(TransportSlice::Udp(udp)) => udp.payload().len(),
            Some(TransportSlice::Icmpv4(ic)) => ic.payload().len(),
            Some(TransportSlice::Icmpv6(ic)) => ic.payload().len(),
            _ => 0,
        };

        Ok(ParsedPacket {
            timestamp: raw.timestamp,
            interface: raw.interface.clone(),
            len: raw.data.len() as u32,
            l3,
            l4,
            app,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ttl,
            flags,
            payload_len,
        })
    }
}
