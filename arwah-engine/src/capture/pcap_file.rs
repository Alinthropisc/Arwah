use async_trait::async_trait;
use b579_core::{
    capture::CaptureSource,
    error::{ArwahError, ArwahResult},
    packet::RawPacket,
    stats::CaptureStats,
};
use chrono::{TimeZone, Utc};
use pcap::{Capture, Offline};
use std::path::Path;
use tracing::debug;

/// Replay packets from an existing `.pcap` / `.pcapng` file.
pub struct PcapFileCapture {
    handle: Capture<Offline>,
    path: String,
}

// SAFETY: Capture<Offline> wraps *mut pcap_t. All ops require &mut self.
unsafe impl Send for PcapFileCapture {}
unsafe impl Sync for PcapFileCapture {}

impl PcapFileCapture {
    pub fn open(path: &Path) -> ArwahResult<Self> {
        let handle = Capture::from_file(path).map_err(|e| ArwahError::Capture(e.to_string()))?;
        debug!(path = %path.display(), "opened pcap file");
        Ok(Self {
            handle,
            path: path.display().to_string(),
        })
    }
}

#[async_trait]
impl CaptureSource for PcapFileCapture {
    async fn next_packet(&mut self) -> ArwahResult<Option<RawPacket>> {
        match self.handle.next_packet() {
            Ok(pkt) => {
                let ts = pkt.header.ts;
                let timestamp = Utc
                    .timestamp_opt(ts.tv_sec as i64, ts.tv_usec as u32 * 1000)
                    .single()
                    .unwrap_or_else(Utc::now);
                Ok(Some(RawPacket {
                    timestamp,
                    interface: self.path.clone(),
                    data: pkt.data.into(),
                }))
            }
            Err(pcap::Error::NoMorePackets) => Ok(None),
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

    fn stats(&mut self) -> ArwahResult<CaptureStats> {
        Ok(CaptureStats::default())
    }

    fn close(self: Box<Self>) {
        drop(self);
    }
}
