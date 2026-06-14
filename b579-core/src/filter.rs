use crate::error::ArwahResult;
use crate::packet::ParsedPacket;

/// A compiled packet filter that can be applied to parsed packets.
///
/// Implementations include BPF-based hardware filters and software
/// display-filter expressions (Wireshark-style DSL).
pub trait PacketFilter: Send + Sync + 'static {
    /// Returns `true` if the packet should be kept (passes the filter).
    fn matches(&self, packet: &ParsedPacket) -> bool;
}

/// A factory that compiles a filter expression string into a [`PacketFilter`].
pub trait FilterCompiler: Send + Sync {
    type Filter: PacketFilter;

    /// Compile `expr` into an executable filter, returning an error if the
    /// syntax is invalid.
    fn compile(&self, expr: &str) -> ArwahResult<Self::Filter>;
}

/// A pass-through filter that accepts every packet.
#[derive(Debug, Clone, Copy)]
pub struct AcceptAll;

impl PacketFilter for AcceptAll {
    #[inline]
    fn matches(&self, _packet: &ParsedPacket) -> bool {
        true
    }
}
