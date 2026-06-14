use b579_core::{
    flow::{FlowKey, FlowRecord, FlowState},
    packet::ParsedPacket,
    protocol::L4Protocol,
};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;

const FLOW_TIMEOUT_SECS: i64 = 120;

/// Lock-free concurrent flow tracking table.
///
/// Uses `DashMap` (sharded `RwLock`) for O(1) insert/lookup under high
/// packet rates without a global mutex.
#[derive(Debug, Default)]
pub struct FlowTracker {
    flows: Arc<DashMap<FlowKey, FlowRecord>>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self { flows: Arc::new(DashMap::with_capacity(8192)) }
    }

    /// Update or create the flow for this packet. Returns the updated record.
    pub fn update(&self, pkt: &ParsedPacket) -> Option<FlowRecord> {
        let key = FlowKey {
            src_ip: pkt.src_ip?,
            dst_ip: pkt.dst_ip?,
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
            protocol: pkt.l4.unwrap_or(L4Protocol::Other(0)),
        }
        .canonical();

        let now = Utc::now();
        let bytes = pkt.len as u64;

        let mut entry = self.flows.entry(key.clone()).or_insert_with(|| FlowRecord {
            key: key.clone(),
            app_protocol: pkt.app,
            state: FlowState::New,
            first_seen: now,
            last_seen: now,
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
        });

        entry.last_seen = now;

        // Forward direction: packet src matches flow src.
        if pkt.src_ip == Some(entry.key.src_ip) {
            entry.packets_fwd += 1;
            entry.bytes_fwd += bytes;
        } else {
            entry.packets_rev += 1;
            entry.bytes_rev += bytes;
        }

        if pkt.flags.is_connection_start() {
            entry.state = FlowState::New;
        } else if pkt.flags.ack && !pkt.flags.fin && !pkt.flags.rst {
            entry.state = FlowState::Established;
        } else if pkt.flags.fin || pkt.flags.rst {
            entry.state = FlowState::Closing;
        }

        Some(entry.clone())
    }

    /// Evict flows that have been idle longer than `FLOW_TIMEOUT_SECS`.
    pub fn evict_stale(&self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(FLOW_TIMEOUT_SECS);
        self.flows.retain(|_, v| v.last_seen > cutoff);
    }

    pub fn active_count(&self) -> usize {
        self.flows.len()
    }

    pub fn snapshot(&self) -> Vec<FlowRecord> {
        self.flows.iter().map(|e| e.value().clone()).collect()
    }
}
