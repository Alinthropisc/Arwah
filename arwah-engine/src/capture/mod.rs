mod live;
mod pcap_file;

#[cfg(target_os = "linux")]
pub mod afpacket;

pub use live::LiveCapture;
pub use pcap_file::PcapFileCapture;
