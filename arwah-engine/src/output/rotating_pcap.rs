//! Rotating PCAP writer — `-C <MB>` (size) and `-G <secs>` (time) semantics,
//! matching tcpdump behaviour. Files are named `<prefix>_NNN.pcap`.

use b579_core::packet::RawPacket;
use pcap::{Capture, Savefile};
use std::{path::PathBuf, time::Instant};

pub struct RotatingPcapWriter {
    prefix: PathBuf,
    max_bytes: Option<u64>,
    max_secs: Option<u64>,
    index: u32,
    current: Option<Savefile>,
    bytes: u64,
    started_at: Instant,
}

impl RotatingPcapWriter {
    /// `max_mb` — rotate after this many megabytes (0 = disabled).
    /// `max_secs` — rotate after this many seconds (0 = disabled).
    pub fn new(prefix: PathBuf, max_mb: u64, max_secs: u64) -> Self {
        Self {
            prefix,
            max_bytes: if max_mb > 0 {
                Some(max_mb * 1024 * 1024)
            } else {
                None
            },
            max_secs: if max_secs > 0 { Some(max_secs) } else { None },
            index: 0,
            current: None,
            bytes: 0,
            started_at: Instant::now(),
        }
    }

    fn next_path(&self) -> PathBuf {
        let mut p = self.prefix.clone();
        let stem = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "capture".to_string());
        p.set_file_name(format!("{stem}_{:03}.pcap", self.index));
        p
    }

    fn open_new(&mut self) -> Result<(), pcap::Error> {
        let path = self.next_path();
        let cap = Capture::dead(pcap::Linktype::ETHERNET)?;
        self.current = Some(cap.savefile(path)?);
        self.bytes = 0;
        self.started_at = Instant::now();
        self.index += 1;
        Ok(())
    }

    fn should_rotate(&self, pkt_len: u64) -> bool {
        self.max_bytes.is_some_and(|max| self.bytes + pkt_len > max)
            || self
                .max_secs
                .is_some_and(|s| self.started_at.elapsed().as_secs() >= s)
    }

    pub fn write(&mut self, pkt: &RawPacket) -> Result<(), pcap::Error> {
        let pkt_len = pkt.data.len() as u64;
        if self.current.is_none() || self.should_rotate(pkt_len) {
            self.open_new()?;
        }
        if let Some(sf) = &mut self.current {
            let header = pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: pkt.timestamp.timestamp() as libc::time_t,
                    tv_usec: pkt.timestamp.timestamp_subsec_micros() as libc::suseconds_t,
                },
                caplen: pkt.data.len() as u32,
                len: pkt.data.len() as u32,
            };
            sf.write(&pcap::Packet::new(&header, &pkt.data));
            self.bytes += pkt_len;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), pcap::Error> {
        if let Some(sf) = &mut self.current {
            sf.flush()?;
        }
        Ok(())
    }
}
