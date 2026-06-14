//! Safe Rust wrappers over the C23 protocol dissectors in proto/.

use std::ffi::CStr;


/* ── Raw C structs (must match proto/proto.h exactly) ───────────────────────── */

#[repr(C)]
#[derive(Debug, Default)]
pub struct EthHdr {
    pub dst:       [u8; 6],
    pub src:       [u8; 6],
    pub ethertype: u16,
    pub vlan_id:   u16,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Ip4Hdr {
    pub ihl:         u8,
    pub dscp:        u8,
    pub ecn:         u8,
    pub total_len:   u16,
    pub id:          u16,
    pub df:          bool,
    pub mf:          bool,
    pub frag_off:    u16,
    pub ttl:         u8,
    pub proto:       u8,
    pub checksum:    u16,
    pub src:         [u8; 4],
    pub dst:         [u8; 4],
    pub checksum_ok: bool,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Ip6Hdr {
    pub tc:          u8,
    pub flow_label:  u32,
    pub payload_len: u16,
    pub next_hdr:    u8,
    pub hop_limit:   u8,
    pub src:         [u8; 16],
    pub dst:         [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq:      u32,
    pub ack:      u32,
    pub data_off: u8,
    pub flags:    u8,
    pub window:   u16,
    pub checksum: u16,
    pub urgent:   u16,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length:   u16,
    pub checksum: u16,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct IcmpHdr {
    pub icmp_type: u8,
    pub code:      u8,
    pub checksum:  u16,
    pub rest:      u32,
}

#[repr(C)]
pub struct DnsHdr {
    pub id:      u16,
    pub qr:      bool,
    pub opcode:  u8,
    pub aa:      bool,
    pub tc:      bool,
    pub rd:      bool,
    pub ra:      bool,
    pub rcode:   u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[repr(C)]
pub struct DnsQuestion {
    pub name:   [u8; 254],
    pub qtype:  u16,
    pub qclass: u16,
}

#[repr(C)]
pub struct TlsRecord {
    pub record_type:     u8,
    pub major_ver:       u8,
    pub minor_ver:       u8,
    pub length:          u16,
    pub is_client_hello: bool,
    pub sni:             [u8; 256],
    pub offered_version: u16,
}

unsafe extern "C" {
    pub fn proto_parse_eth (pkt: *const u8, len: usize, out: *mut EthHdr)  -> usize;
    pub fn proto_parse_ip4 (pkt: *const u8, len: usize, out: *mut Ip4Hdr)  -> usize;
    pub fn proto_parse_ip6 (pkt: *const u8, len: usize, out: *mut Ip6Hdr)  -> usize;
    pub fn proto_parse_tcp (pkt: *const u8, len: usize, out: *mut TcpHdr)  -> usize;
    pub fn proto_parse_udp (pkt: *const u8, len: usize, out: *mut UdpHdr)  -> usize;
    pub fn proto_parse_icmp(pkt: *const u8, len: usize, out: *mut IcmpHdr) -> usize;
    pub fn proto_parse_dns (pkt: *const u8, len: usize, hdr: *mut DnsHdr, q: *mut DnsQuestion) -> usize;
    pub fn proto_parse_tls (pkt: *const u8, len: usize, out: *mut TlsRecord) -> usize;
    pub fn proto_inet_checksum(data: *const u8, len: usize) -> u16;
}

/* ── Safe wrappers ────────────────────────────────────────────────────────── */

pub fn parse_ip4(buf: &[u8]) -> Option<(Ip4Hdr, usize)> {
    let mut h = Ip4Hdr::default();
    let consumed = unsafe { proto_parse_ip4(buf.as_ptr(), buf.len(), &mut h) };
    if consumed == 0 { None } else { Some((h, consumed)) }
}

pub fn parse_tcp(buf: &[u8]) -> Option<(TcpHdr, usize)> {
    let mut h = TcpHdr::default();
    let consumed = unsafe { proto_parse_tcp(buf.as_ptr(), buf.len(), &mut h) };
    if consumed == 0 { None } else { Some((h, consumed)) }
}

pub fn parse_udp(buf: &[u8]) -> Option<(UdpHdr, usize)> {
    let mut h = UdpHdr::default();
    let consumed = unsafe { proto_parse_udp(buf.as_ptr(), buf.len(), &mut h) };
    if consumed == 0 { None } else { Some((h, consumed)) }
}

/// Extract the SNI hostname from a TLS ClientHello, if present.
pub fn tls_sni(buf: &[u8]) -> Option<String> {
    let mut rec = TlsRecord {
        record_type: 0, major_ver: 0, minor_ver: 0,
        length: 0, is_client_hello: false,
        sni: [0u8; 256], offered_version: 0,
    };
    let consumed = unsafe { proto_parse_tls(buf.as_ptr(), buf.len(), &mut rec) };
    if consumed == 0 || !rec.is_client_hello || rec.sni[0] == 0 {
        return None;
    }
    CStr::from_bytes_until_nul(&rec.sni)
        .ok()
        .map(|cs| cs.to_string_lossy().into_owned())
}

/// Extract the first DNS question name.
pub fn dns_query_name(buf: &[u8]) -> Option<String> {
    let mut hdr = DnsHdr {
        id: 0, qr: false, opcode: 0, aa: false, tc: false,
        rd: false, ra: false, rcode: 0,
        qdcount: 0, ancount: 0, nscount: 0, arcount: 0,
    };
    let mut q = DnsQuestion { name: [0u8; 254], qtype: 0, qclass: 0 };
    let consumed = unsafe { proto_parse_dns(buf.as_ptr(), buf.len(), &mut hdr, &mut q) };
    if consumed == 0 || hdr.qdcount == 0 { return None; }
    CStr::from_bytes_until_nul(&q.name)
        .ok()
        .map(|cs| cs.to_string_lossy().into_owned())
}

/// Verify IPv4 header checksum.
pub fn ipv4_checksum_valid(hdr_bytes: &[u8]) -> bool {
    unsafe { proto_inet_checksum(hdr_bytes.as_ptr(), hdr_bytes.len()) == 0 }
}
