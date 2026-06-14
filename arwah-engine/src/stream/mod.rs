//! TCP stream reassembler. Inspired by tcpdump follow-stream.

use b579_core::flow::FlowKey;
use std::collections::{BTreeMap, HashMap};

const MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Default)]
pub struct HalfStream { segments: BTreeMap<u32, Vec<u8>>, next_seq: u32, total: usize }

impl HalfStream {
    fn push(&mut self, seq: u32, data: Vec<u8>) {
        if data.is_empty() || self.total + data.len() > MAX_BYTES { return; }
        self.total += data.len();
        self.segments.insert(seq, data);
    }

    fn drain(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let Some((&seq, _)) = self.segments.iter().next() else { break };
            if seq > self.next_seq { break; }
            let data = self.segments.remove(&seq).unwrap();
            let skip = self.next_seq.wrapping_sub(seq) as usize;
            if skip < data.len() {
                let useful = &data[skip..];
                self.next_seq = self.next_seq.wrapping_add(useful.len() as u32);
                out.extend_from_slice(useful);
            }
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct TcpStream { pub client: HalfStream, pub server: HalfStream, pub closed: bool }

pub struct StreamTable { streams: HashMap<FlowKey, TcpStream> }

impl StreamTable {
    pub fn new() -> Self { Self { streams: HashMap::with_capacity(1024) } }

    /// Returns (client→server reassembled, server→client reassembled).
    pub fn feed(&mut self, key: &FlowKey, fwd: bool, seq: u32, flags: u8, data: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let s = self.streams.entry(key.clone()).or_default();
        if flags & 0x06 != 0 { s.closed = true; }                   // FIN or RST
        if flags & 0x02 != 0 {                                       // SYN
            let hs = if fwd { &mut s.client } else { &mut s.server };
            hs.next_seq = seq.wrapping_add(1);
        }
        if !data.is_empty() {
            if fwd { s.client.push(seq, data); } else { s.server.push(seq, data); }
        }
        (s.client.drain(), s.server.drain())
    }

    pub fn remove(&mut self, key: &FlowKey) { self.streams.remove(key); }
    pub fn len(&self) -> usize { self.streams.len() }
}

impl Default for StreamTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use b579_core::protocol::L4Protocol;
    use std::net::IpAddr;

    fn key() -> FlowKey {
        FlowKey { src_ip: IpAddr::from([10,0,0,1]), dst_ip: IpAddr::from([10,0,0,2]),
                  src_port: 1234, dst_port: 80, protocol: L4Protocol::Tcp }
    }

    #[test]
    fn in_order() {
        let mut t = StreamTable::new();
        let k = key();
        t.feed(&k, true, 0, 0x02, vec![]);
        let (a, _) = t.feed(&k, true, 1, 0x18, b"Hello ".to_vec());
        assert_eq!(a, b"Hello ");
        let (b2, _) = t.feed(&k, true, 7, 0x18, b"World".to_vec());
        assert_eq!(b2, b"World");
    }
}
