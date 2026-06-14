#![allow(dead_code)]

/// Mirrors `BpfInsn` in bpf/bpf.h.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Mirrors `BpfProg` in bpf/bpf.h.
#[repr(C)]
pub struct BpfProg {
    pub insns: *const BpfInsn,
    pub len: usize,
}

/// Mirrors `BpfPkt` in bpf/bpf.h.
#[repr(C)]
pub struct BpfPkt {
    pub data: *const u8,
    pub cap_len: u32,
    pub wire_len: u32,
}

unsafe extern "C" {
    pub fn bpf_exec(prog: *const BpfProg, pkt: *const BpfPkt) -> u32;
    pub fn bpf_validate(prog: *const BpfProg) -> bool;
}

/// Execute a BPF program against a packet slice.
/// Returns bytes to accept (0 = drop).
///
/// # Safety
/// `prog` must be a valid, validated BPF program. Use [`bpf_validate_safe`] first.
pub fn exec(insns: &[BpfInsn], pkt: &[u8], wire_len: u32) -> u32 {
    let prog = BpfProg {
        insns: insns.as_ptr(),
        len: insns.len(),
    };
    let bpf_pkt = BpfPkt {
        data: pkt.as_ptr(),
        cap_len: pkt.len() as u32,
        wire_len,
    };
    unsafe { bpf_exec(&prog, &bpf_pkt) }
}

/// Validate a BPF program before execution.
pub fn validate(insns: &[BpfInsn]) -> bool {
    let prog = BpfProg {
        insns: insns.as_ptr(),
        len: insns.len(),
    };
    unsafe { bpf_validate(&prog) }
}
