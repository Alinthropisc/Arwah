use async_trait::async_trait;
use b579_core::{
    capture::CaptureSource,
    error::{ArwahError, ArwahResult},
    packet::RawPacket,
    stats::CaptureStats,
};
use chrono::Utc;
use pcap::{Active, Capture};
use tracing::debug;

/// Live packet capture from a network interface via libpcap.
pub struct LiveCapture {
    handle: Capture<Active>,
    interface: String,
}

// SAFETY: Capture<Active> wraps a raw *mut pcap_t. All operations on the
// handle require &mut self, so only one thread can access it at a time.
// We never clone or share the raw pointer.
unsafe impl Send for LiveCapture {}
unsafe impl Sync for LiveCapture {}

impl LiveCapture {
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
        Ok(Self {
            handle,
            interface: interface.to_owned(),
        })
    }
}

#[async_trait]
impl CaptureSource for LiveCapture {
    async fn next_packet(&mut self) -> ArwahResult<Option<RawPacket>> {
        match self.handle.next_packet() {
            Ok(pkt) => Ok(Some(RawPacket {
                timestamp: Utc::now(),
                interface: self.interface.clone(),
                data: pkt.data.into(),
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(ArwahError::Capture(e.to_string())),
        }
    }

    fn set_bpf_filter(&mut self, expr: &str) -> ArwahResult<()> {
        self.handle
            .filter(expr, true)
            .map_err(|e| ArwahError::FilterSyntax { pos: 0, msg: e.to_string() })
    }

    fn stats(&mut self) -> ArwahResult<CaptureStats> {
        let s = self
            .handle
            .stats()
            .map_err(|e| ArwahError::Capture(e.to_string()))?;
        Ok(CaptureStats {
            received: s.received as u64,
            dropped_kernel: s.dropped as u64,
            dropped_iface: s.if_dropped as u64,
        })
    }

    fn close(self: Box<Self>) {
        drop(self);
    }
}
