use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::tui;

/// B579-Arwah — next-generation network traffic analyzer and security sniffer.
#[derive(Parser, Debug)]
#[command(
    name    = "arwah",
    version = env!("CARGO_PKG_VERSION"),
    author  = "B579-Arwah Contributors",
    about   = "Powerful async network sniffer with TUI and deep protocol analysis",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Network interface to capture from (default: auto-detect first non-loopback)
    #[arg(short, long, global = true, env = "ARWAH_INTERFACE")]
    pub interface: Option<String>,

    /// BPF capture filter expression (e.g. "tcp port 443")
    #[arg(short = 'f', long, global = true)]
    pub bpf: Option<String>,

    /// Enable verbose logging (repeat for more: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Output format for headless commands
    #[arg(short = 'o', long, default_value = "table", global = true)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the interactive TUI dashboard (default when no subcommand given)
    Watch {
        /// Refresh interval in milliseconds
        #[arg(short, long, default_value = "500")]
        interval_ms: u64,
    },
    /// One-shot packet capture: capture N packets and print them
    Capture {
        /// Number of packets to capture (0 = unlimited until Ctrl-C)
        #[arg(short = 'n', long, default_value = "0")]
        count: u64,

        /// Write captured packets to a PCAP file
        #[arg(short = 'w', long)]
        write: Option<PathBuf>,
    },
    /// Read and analyse an existing PCAP file
    Read {
        /// Path to .pcap or .pcapng file
        file: PathBuf,

        /// Display filter expression (e.g. "tcp and port == 443")
        #[arg(short = 'd', long)]
        display_filter: Option<String>,
    },
    /// Show real-time traffic statistics
    Stats {
        /// Duration in seconds to gather stats (0 = run until Ctrl-C)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },
    /// List available network interfaces
    Interfaces,
    /// Show active network flows
    Flows {
        /// Sort column: bytes | packets | duration
        #[arg(short, long, default_value = "bytes")]
        sort: FlowSort,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum FlowSort {
    Bytes,
    Packets,
    Duration,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command.unwrap_or(Command::Watch { interval_ms: 500 }) {
            Command::Watch { interval_ms } => {
                tui::run(self.interface.as_deref(), self.bpf.as_deref(), interval_ms)
            }
            Command::Interfaces => {
                list_interfaces();
                Ok(())
            }
            Command::Capture { count, write } => {
                run_capture(self.interface.as_deref(), self.bpf.as_deref(), count, write)
            }
            Command::Read { file, display_filter } => {
                run_read(file, display_filter.as_deref())
            }
            Command::Stats { duration } => {
                run_stats(self.interface.as_deref(), self.bpf.as_deref(), duration)
            }
            Command::Flows { sort } => {
                run_flows(self.interface.as_deref(), self.bpf.as_deref(), sort)
            }
        }
    }
}

fn list_interfaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            println!("{:<20} {}", "INTERFACE", "DESCRIPTION");
            println!("{}", "-".repeat(60));
            for dev in devices {
                println!("{:<20} {}", dev.name, dev.desc.unwrap_or_default());
            }
        }
        Err(e) => eprintln!("error listing interfaces: {e}"),
    }
}

fn run_capture(
    iface: Option<&str>,
    bpf: Option<&str>,
    count: u64,
    _write: Option<PathBuf>,
) -> Result<()> {
    use arwah_engine::capture::LiveCapture;
    use b579_core::capture::CaptureSource;

    let iface = resolve_interface(iface)?;
    let mut cap = LiveCapture::open(&iface)?;
    if let Some(expr) = bpf {
        cap.set_bpf_filter(expr)?;
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use arwah_engine::analysis::EtherparseDecoder;
        let decoder = EtherparseDecoder;
        let mut cap = Box::new(cap) as Box<dyn CaptureSource>;
        let mut captured = 0u64;

        loop {
            if count > 0 && captured >= count {
                break;
            }
            match cap.next_packet().await? {
                Some(raw) => {
                    captured += 1;
                    match decoder.decode(&raw) {
                        Ok(pkt) => {
                            println!(
                                "[{}] {} {:?} {}:{} → {}:{} ({} bytes)",
                                pkt.timestamp.format("%H:%M:%S%.3f"),
                                pkt.interface,
                                pkt.l4.map(|p| format!("{p:?}")).unwrap_or_default(),
                                pkt.src_ip.map(|i| i.to_string()).unwrap_or_default(),
                                pkt.src_port.unwrap_or(0),
                                pkt.dst_ip.map(|i| i.to_string()).unwrap_or_default(),
                                pkt.dst_port.unwrap_or(0),
                                pkt.len,
                            );
                        }
                        Err(e) => tracing::debug!("decode error: {e}"),
                    }
                }
                None => break,
            }
        }

        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}

fn run_read(file: PathBuf, display_filter: Option<&str>) -> Result<()> {
    use arwah_engine::{analysis::EtherparseDecoder, capture::PcapFileCapture};
    use b579_core::{capture::CaptureSource, filter::PacketFilter};
    use arwah_engine::filter::DisplayFilter;

    let filter: Option<DisplayFilter> = display_filter
        .map(DisplayFilter::parse)
        .transpose()?;

    let src = PcapFileCapture::open(&file)?;
    let decoder = EtherparseDecoder;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let mut src = Box::new(src) as Box<dyn CaptureSource>;
        let mut count = 0u64;

        loop {
            match src.next_packet().await? {
                Some(raw) => {
                    let pkt = match decoder.decode(&raw) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(ref f) = filter {
                        if !f.matches(&pkt) {
                            continue;
                        }
                    }
                    count += 1;
                    println!(
                        "{} {:?} {}:{} → {}:{} {} bytes",
                        pkt.timestamp.format("%H:%M:%S%.6f"),
                        pkt.l4,
                        pkt.src_ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into()),
                        pkt.src_port.unwrap_or(0),
                        pkt.dst_ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into()),
                        pkt.dst_port.unwrap_or(0),
                        pkt.len,
                    );
                }
                None => break,
            }
        }
        println!("\n{count} packets");
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

fn run_stats(iface: Option<&str>, bpf: Option<&str>, duration: u64) -> Result<()> {
    let iface = resolve_interface(iface)?;
    println!("Collecting stats on {iface}… (Ctrl-C to stop)");
    // Headless stats mode — real-time loop with periodic snapshots.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use arwah_engine::{capture::LiveCapture, session::CaptureSession};
        use b579_core::capture::CaptureSource;

        let mut cap = LiveCapture::open(&iface)?;
        if let Some(expr) = bpf {
            cap.set_bpf_filter(expr)?;
        }

        let session = std::sync::Arc::new(CaptureSession::new());
        let session_clone = session.clone();

        tokio::spawn(async move {
            session_clone.run(Box::new(cap)).await;
        });

        let deadline = if duration > 0 {
            Some(tokio::time::Instant::now() + tokio::time::Duration::from_secs(duration))
        } else {
            None
        };

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let snap = session.snapshot();
            println!(
                "packets: {}  bytes: {}  flows: {}",
                snap.total_packets,
                snap.total_bytes,
                session.active_flows().len()
            );
            if let Some(dl) = deadline {
                if tokio::time::Instant::now() >= dl {
                    break;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

fn run_flows(iface: Option<&str>, bpf: Option<&str>, sort: FlowSort) -> Result<()> {
    let iface = resolve_interface(iface)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use arwah_engine::{capture::LiveCapture, session::CaptureSession};
        use b579_core::capture::CaptureSource;

        let mut cap = LiveCapture::open(&iface)?;
        if let Some(expr) = bpf {
            cap.set_bpf_filter(expr)?;
        }

        let session = std::sync::Arc::new(CaptureSession::new());
        let session_clone = session.clone();

        tokio::spawn(async move {
            session_clone.run(Box::new(cap)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        let mut flows = session.active_flows();

        match sort {
            FlowSort::Bytes    => flows.sort_unstable_by(|a, b| b.total_bytes().cmp(&a.total_bytes())),
            FlowSort::Packets  => flows.sort_unstable_by(|a, b| b.total_packets().cmp(&a.total_packets())),
            FlowSort::Duration => flows.sort_unstable_by(|a, b| b.duration_ms().cmp(&a.duration_ms())),
        }

        println!("{:<45} {:<45} {:>10} {:>10}", "SRC", "DST", "BYTES", "PKTS");
        println!("{}", "-".repeat(115));
        for f in flows.iter().take(30) {
            println!(
                "{:<45} {:<45} {:>10} {:>10}",
                format!("{}:{}", f.key.src_ip, f.key.src_port),
                format!("{}:{}", f.key.dst_ip, f.key.dst_port),
                f.total_bytes(),
                f.total_packets(),
            );
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

fn resolve_interface(iface: Option<&str>) -> Result<String> {
    if let Some(i) = iface {
        return Ok(i.to_owned());
    }
    // Auto-detect: first non-loopback device.
    let devices = pcap::Device::list().map_err(|e| anyhow::anyhow!("pcap: {e}"))?;
    devices
        .into_iter()
        .find(|d| d.name != "lo")
        .map(|d| d.name)
        .ok_or_else(|| anyhow::anyhow!("no suitable network interface found"))
}
