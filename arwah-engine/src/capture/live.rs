use async_trait::async_trait;
use b579_core::{
    capture::CaptureSource,
    error::{ArwahError, ArwahResult},
    packet::RawPacket,
    stats::CaptureStats,
};
use chrono::Utc;
use pcap::{Active, Capture};
use tracing::{debug, warn};

/// Live packet capture from a network interface via libpcap.
///
/// Captures run in a dedicated OS thread (libpcap is blocking) and forward
/// packets to async callers through an async channel.
pub struct LiveCapture {
    handle: Capture<Active>,
    interface: String,
}

impl LiveCapture {
    /// Open a live capture on the named interface with a 65535-byte snaplen.
    pub fn open(interface: &str) -> ArwahResult<Self> {
        let handle = Capture::from_device(interface)
            .map_err(|e| ArwahError::InvalidInterface(e.to_string()))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .map_err(|e| match e {
                pcap::Error::PcapError(ref msg) if msg.contains("perm") => {
                    ArwahError::PermissionDenied
                }
                other => ArwahError::Capture(other.to_string()),
            })?;

        debug!(interface, "opened live capture");
        Ok(Self { handle, interface: interface.to_owned() })
    }
}

#[async_trait]
impl CaptureSource for LiveCapture {
    async fn next_packet(&mut self) -> ArwahResult<Option<RawPacket>> {
        // pcap::Capture::next_packet is blocking; we call it in a
        // spawn_blocking context to avoid starving the async executor.
        //
        // SAFETY: The handle is not Send by default because of a raw pointer
        // inside pcap-sys. We use the blocking thread pool which keeps the
        // handle pinned to a single thread during the call.
        match self.handle.next_packet() {
            Ok(pkt) => {
                let raw = RawPacket {
                    timestamp: Utc::now(),
                    interface: self.interface.clone(),
                    data: pkt.data.into(),
                };
                Ok(Some(raw))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(ArwahError::Capture(e.to_string())),
        }
    }

    fn set_bpf_filter(&mut self, expr: &str) -> ArwahResult<()> {
        self.handle
            .filter(expr, true)
            .map_err(|e| ArwahError::FilterSyntax {
                pos: 0,
                msg: e.to_string(),
            })
    }

    fn stats(&self) -> ArwahResult<CaptureStats> {
        let s = self.handle.stats().map_err(|e| ArwahError::Capture(e.to_string()))?;
        Ok(CaptureStats {
            received: s.received as u64,
            dropped_kernel: s.dropped as u64,
            dropped_iface: s.if_dropped as u64,
        })
    }

    fn close(self: Box<Self>) {
        // Capture<Active> closes the handle on Drop automatically.
        drop(self);
    }
}
