//! AF_PACKET zero-copy capture (Linux only). Inspired by netsniff-ng.
#![cfg(target_os = "linux")]

use async_trait::async_trait;
use b579_core::{capture::CaptureSource, error::{ArwahError, ArwahResult}, packet::RawPacket, stats::CaptureStats};
use chrono::Utc;
use std::ffi::CString;
use tracing::info;

pub struct AfPacketCapture { fd: i32, interface: String, closed: bool }

impl AfPacketCapture {
    pub fn open(interface: &str) -> ArwahResult<Self> {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            return if unsafe { *libc::__errno_location() } == libc::EPERM {
                Err(ArwahError::PermissionDenied)
            } else {
                Err(ArwahError::Capture("socket() failed".into()))
            };
        }
        let iface = CString::new(interface).map_err(|_| ArwahError::InvalidInterface(interface.into()))?;
        let idx = unsafe { libc::if_nametoindex(iface.as_ptr()) };
        if idx == 0 { unsafe { libc::close(fd) }; return Err(ArwahError::InvalidInterface(interface.into())); }
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = idx as i32;
        let rc = unsafe { libc::bind(fd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) };
        if rc < 0 { unsafe { libc::close(fd) }; return Err(ArwahError::Capture("bind() failed".into())); }
        info!(interface, "AF_PACKET socket ready");
        Ok(Self { fd, interface: interface.to_owned(), closed: false })
    }
}

#[async_trait]
impl CaptureSource for AfPacketCapture {
    async fn next_packet(&mut self) -> ArwahResult<Option<RawPacket>> {
        if self.closed { return Ok(None); }
        let mut buf = vec![0u8; 65536];
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 { return Err(ArwahError::Capture("recv() failed".into())); }
        buf.truncate(n as usize);
        Ok(Some(RawPacket { timestamp: Utc::now(), interface: self.interface.clone(), data: buf.into_boxed_slice() }))
    }
    fn set_bpf_filter(&mut self, _: &str) -> ArwahResult<()> { Ok(()) }
    fn stats(&mut self) -> ArwahResult<CaptureStats> { Ok(CaptureStats::default()) }
    fn close(mut self: Box<Self>) { if !self.closed { unsafe { libc::close(self.fd) }; self.closed = true; } }
}

impl Drop for AfPacketCapture {
    fn drop(&mut self) { if !self.closed { unsafe { libc::close(self.fd) }; } }
}
