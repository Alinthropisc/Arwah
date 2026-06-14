use crate::{
    analysis::{EtherparseDecoder, FlowTracker},
    stats::StatsEngine,
};
use b579_core::{
    capture::CaptureSource,
    flow::FlowRecord,
    packet::ParsedPacket,
    stats::TrafficSnapshot,
};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

const BROADCAST_CAP: usize = 4096;

/// Orchestrates capture, decoding, flow tracking, and statistics collection.
///
/// Wrap in `Arc<CaptureSession>` to share across tasks and the TUI thread.
pub struct CaptureSession {
    decoder: EtherparseDecoder,
    pub flow_tracker: Arc<FlowTracker>,
    pub stats: Arc<StatsEngine>,
    pub tx: broadcast::Sender<ParsedPacket>,
}

impl CaptureSession {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            decoder: EtherparseDecoder,
            flow_tracker: Arc::new(FlowTracker::new()),
            stats: Arc::new(StatsEngine::new()),
            tx,
        }
    }

    /// Subscribe to the real-time parsed-packet broadcast stream.
    pub fn subscribe(&self) -> broadcast::Receiver<ParsedPacket> {
        self.tx.subscribe()
    }

    /// Drive the capture loop until the source is exhausted or errors out.
    ///
    /// Designed to run inside `tokio::spawn`.
    pub async fn run(self: Arc<Self>, mut source: Box<dyn CaptureSource>) {
        info!("capture session started");

        loop {
            match source.next_packet().await {
                Ok(Some(raw)) => {
                    let pkt = match self.decoder.decode(&raw) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::debug!("decode skipped: {e}");
                            continue;
                        }
                    };
                    self.stats.record(&pkt);
                    self.flow_tracker.update(&pkt);
                    let _ = self.tx.send(pkt);
                }
                Ok(None) => {
                    info!("capture source exhausted");
                    break;
                }
                Err(e) => {
                    error!("capture error: {e}");
                    break;
                }
            }
        }

        source.close();
        info!("capture session stopped");
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        self.stats.snapshot()
    }

    pub fn active_flows(&self) -> Vec<FlowRecord> {
        self.flow_tracker.snapshot()
    }
}

impl Default for CaptureSession {
    fn default() -> Self {
        Self::new()
    }
}
