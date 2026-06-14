use async_trait::async_trait;

use crate::error::ArwahResult;
use crate::packet::RawPacket;
use crate::stats::CaptureStats;

/// Abstraction over a packet capture source (live interface or PCAP file).
///
/// Implementors must be `Send + Sync` to allow use across async task boundaries.
#[async_trait]
pub trait CaptureSource: Send + Sync {
    /// Receive the next available packet, blocking asynchronously until one
    /// arrives or the capture is stopped.
    async fn next_packet(&mut self) -> ArwahResult<Option<RawPacket>>;

    /// Apply a BPF filter expression to the capture source.
    ///
    /// Must be called before [`next_packet`](Self::next_packet) is first invoked.
    fn set_bpf_filter(&mut self, expr: &str) -> ArwahResult<()>;

    /// Query kernel-level capture statistics (received / dropped).
    fn stats(&self) -> ArwahResult<CaptureStats>;

    /// Cleanly close the capture source and release kernel resources.
    fn close(self: Box<Self>);
}
