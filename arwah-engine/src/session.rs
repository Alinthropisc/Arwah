use crate::{
    alert::AlertEngine,
    analysis::{EtherparseDecoder, FlowTracker},
    stats::StatsEngine,
};
use b579_core::{
    alert::Alert, capture::CaptureSource, flow::FlowRecord, packet::ParsedPacket,
    stats::TrafficSnapshot,
};
use std::sync::Arc;
use tokio::{sync::broadcast, time};
use tracing::{error, info};

const BROADCAST_CAP: usize = 4096;
const EVICT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Orchestrates capture, decoding, flow tracking, statistics, and alerting.
///
/// Wrap in `Arc<CaptureSession>` to share across tasks and the TUI thread.
pub struct CaptureSession {
    decoder: EtherparseDecoder,
    pub flow_tracker: Arc<FlowTracker>,
    pub stats: Arc<StatsEngine>,
    pub alerts: Arc<AlertEngine>,
    pub tx: broadcast::Sender<ParsedPacket>,
}

impl CaptureSession {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            decoder: EtherparseDecoder,
            flow_tracker: Arc::new(FlowTracker::new()),
            stats: Arc::new(StatsEngine::new()),
            alerts: Arc::new(AlertEngine::new()),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ParsedPacket> {
        self.tx.subscribe()
    }

    pub fn subscribe_alerts(&self) -> broadcast::Receiver<Alert> {
        self.alerts.subscribe()
    }

    /// Drive the capture loop until the source is exhausted or errors out.
    pub async fn run(self: Arc<Self>, mut source: Box<dyn CaptureSource>) {
        info!("capture session started");

        // Background task: evict stale flows every 30 s and run FlowRules.
        let session = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(EVICT_INTERVAL);
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                let evicted = session.flow_tracker.evict_stale();
                for flow in &evicted {
                    session.alerts.inspect_flow(flow);
                }
            }
        });

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
                    self.alerts.inspect(&pkt);
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
