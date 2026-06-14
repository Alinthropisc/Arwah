use b579_core::{
    error::{ArwahError, ArwahResult},
    filter::PacketFilter,
    packet::ParsedPacket,
    protocol::{AppProtocol, L4Protocol},
};
use std::net::IpAddr;

/// Simple display-filter expression for post-capture filtering.
///
/// Supported predicates (combinable with `and`/`or`/`not`):
/// - `tcp`, `udp`, `icmp`
/// - `http`, `dns`, `ssh`, …
/// - `ip.src == 1.2.3.4`, `ip.dst == 1.2.3.4`
/// - `port == 443`, `src.port == 80`
#[derive(Debug, Clone)]
pub struct DisplayFilter {
    expr: String,
    predicate: FilterPredicate,
}

#[derive(Debug, Clone)]
enum FilterPredicate {
    Proto(L4Protocol),
    App(AppProtocol),
    SrcIp(IpAddr),
    DstIp(IpAddr),
    Port(u16),
    SrcPort(u16),
    DstPort(u16),
    And(Box<FilterPredicate>, Box<FilterPredicate>),
    Or(Box<FilterPredicate>, Box<FilterPredicate>),
    Not(Box<FilterPredicate>),
}

impl DisplayFilter {
    pub fn parse(expr: &str) -> ArwahResult<Self> {
        let predicate = parse_expr(expr.trim())?;
        Ok(Self {
            expr: expr.to_owned(),
            predicate,
        })
    }

    pub fn expression(&self) -> &str {
        &self.expr
    }
}

impl PacketFilter for DisplayFilter {
    fn matches(&self, pkt: &ParsedPacket) -> bool {
        eval(&self.predicate, pkt)
    }
}

fn eval(pred: &FilterPredicate, pkt: &ParsedPacket) -> bool {
    match pred {
        FilterPredicate::Proto(p) => pkt.l4.as_ref() == Some(p),
        FilterPredicate::App(a) => &pkt.app == a,
        FilterPredicate::SrcIp(ip) => pkt.src_ip.as_ref() == Some(ip),
        FilterPredicate::DstIp(ip) => pkt.dst_ip.as_ref() == Some(ip),
        FilterPredicate::Port(p) => pkt.src_port == Some(*p) || pkt.dst_port == Some(*p),
        FilterPredicate::SrcPort(p) => pkt.src_port == Some(*p),
        FilterPredicate::DstPort(p) => pkt.dst_port == Some(*p),
        FilterPredicate::And(a, b) => eval(a, pkt) && eval(b, pkt),
        FilterPredicate::Or(a, b) => eval(a, pkt) || eval(b, pkt),
        FilterPredicate::Not(inner) => !eval(inner, pkt),
    }
}

fn parse_expr(s: &str) -> ArwahResult<FilterPredicate> {
    // Split on top-level `or` / `and` (left-to-right, lowest precedence first).
    if let Some(idx) = top_level_split(s, " or ") {
        let l = parse_expr(s[..idx].trim())?;
        let r = parse_expr(s[idx + 4..].trim())?;
        return Ok(FilterPredicate::Or(Box::new(l), Box::new(r)));
    }
    if let Some(idx) = top_level_split(s, " and ") {
        let l = parse_expr(s[..idx].trim())?;
        let r = parse_expr(s[idx + 5..].trim())?;
        return Ok(FilterPredicate::And(Box::new(l), Box::new(r)));
    }
    if let Some(rest) = s.strip_prefix("not ") {
        let inner = parse_expr(rest.trim())?;
        return Ok(FilterPredicate::Not(Box::new(inner)));
    }

    parse_atom(s)
}

fn parse_atom(s: &str) -> ArwahResult<FilterPredicate> {
    match s {
        "tcp" => return Ok(FilterPredicate::Proto(L4Protocol::Tcp)),
        "udp" => return Ok(FilterPredicate::Proto(L4Protocol::Udp)),
        "icmp" => return Ok(FilterPredicate::Proto(L4Protocol::Icmp)),
        "http" => return Ok(FilterPredicate::App(AppProtocol::Http)),
        "https" => return Ok(FilterPredicate::App(AppProtocol::Https)),
        "dns" => return Ok(FilterPredicate::App(AppProtocol::Dns)),
        "ssh" => return Ok(FilterPredicate::App(AppProtocol::Ssh)),
        "ftp" => return Ok(FilterPredicate::App(AppProtocol::Ftp)),
        _ => {}
    }

    if let Some(rhs) = s.strip_prefix("ip.src == ") {
        let ip: IpAddr = rhs.trim().parse().map_err(|_| ArwahError::FilterSyntax {
            pos: 7,
            msg: format!("invalid IP address: {rhs}"),
        })?;
        return Ok(FilterPredicate::SrcIp(ip));
    }
    if let Some(rhs) = s.strip_prefix("ip.dst == ") {
        let ip: IpAddr = rhs.trim().parse().map_err(|_| ArwahError::FilterSyntax {
            pos: 7,
            msg: format!("invalid IP address: {rhs}"),
        })?;
        return Ok(FilterPredicate::DstIp(ip));
    }
    if let Some(rhs) = s.strip_prefix("port == ") {
        let p: u16 = rhs.trim().parse().map_err(|_| ArwahError::FilterSyntax {
            pos: 7,
            msg: format!("invalid port: {rhs}"),
        })?;
        return Ok(FilterPredicate::Port(p));
    }
    if let Some(rhs) = s.strip_prefix("src.port == ") {
        let p: u16 = rhs.trim().parse().map_err(|_| ArwahError::FilterSyntax {
            pos: 11,
            msg: format!("invalid port: {rhs}"),
        })?;
        return Ok(FilterPredicate::SrcPort(p));
    }
    if let Some(rhs) = s.strip_prefix("dst.port == ") {
        let p: u16 = rhs.trim().parse().map_err(|_| ArwahError::FilterSyntax {
            pos: 11,
            msg: format!("invalid port: {rhs}"),
        })?;
        return Ok(FilterPredicate::DstPort(p));
    }

    Err(ArwahError::FilterSyntax {
        pos: 0,
        msg: format!("unknown filter expression: '{s}'"),
    })
}

// Find the first occurrence of `needle` that is not inside parentheses.
fn top_level_split(haystack: &str, needle: &str) -> Option<usize> {
    let mut depth = 0usize;
    let bytes = haystack.as_bytes();
    let n = needle.len();
    for i in 0..bytes.len().saturating_sub(n) {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && haystack[i..].starts_with(needle) {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use b579_core::packet::ParsedPacket;
    use b579_core::protocol::{AppProtocol, L3Protocol, L4Protocol};
    use chrono::Utc;

    fn make_packet(l4: Option<L4Protocol>, app: AppProtocol, dst_port: Option<u16>) -> ParsedPacket {
        ParsedPacket {
            timestamp: Utc::now(),
            interface: "eth0".into(),
            len: 60,
            l3: L3Protocol::IPv4,
            l4,
            app,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port,
            ttl: None,
            flags: Default::default(),
            payload_len: 0,
        }
    }

    #[test]
    fn filter_tcp_matches() {
        let f = DisplayFilter::parse("tcp").unwrap();
        let pkt = make_packet(Some(L4Protocol::Tcp), AppProtocol::Unknown, None);
        assert!(f.matches(&pkt));
    }

    #[test]
    fn filter_tcp_rejects_udp() {
        let f = DisplayFilter::parse("tcp").unwrap();
        let pkt = make_packet(Some(L4Protocol::Udp), AppProtocol::Unknown, None);
        assert!(!f.matches(&pkt));
    }

    #[test]
    fn filter_or_combines() {
        let f = DisplayFilter::parse("tcp or udp").unwrap();
        let tcp = make_packet(Some(L4Protocol::Tcp), AppProtocol::Unknown, None);
        let udp = make_packet(Some(L4Protocol::Udp), AppProtocol::Unknown, None);
        assert!(f.matches(&tcp));
        assert!(f.matches(&udp));
    }

    #[test]
    fn filter_port_matches() {
        let f = DisplayFilter::parse("port == 443").unwrap();
        let pkt = make_packet(Some(L4Protocol::Tcp), AppProtocol::Https, Some(443));
        assert!(f.matches(&pkt));
    }

    #[test]
    fn filter_not_negates() {
        let f = DisplayFilter::parse("not tcp").unwrap();
        let pkt = make_packet(Some(L4Protocol::Tcp), AppProtocol::Unknown, None);
        assert!(!f.matches(&pkt));
    }

    #[test]
    fn invalid_ip_returns_error() {
        assert!(DisplayFilter::parse("ip.src == not-an-ip").is_err());
    }
}
