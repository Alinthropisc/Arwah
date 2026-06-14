#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ── BPF instruction ───────────────────────────────────────────────────────── */
typedef struct {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
} BpfInsn;

/* ── BPF program (array of instructions + length) ─────────────────────────── */
typedef struct {
    BpfInsn *insns;
    size_t   len;
} BpfProg;

/* ── Packet buffer passed to the BPF executor ─────────────────────────────── */
typedef struct {
    const uint8_t *data;
    uint32_t       cap_len;  /* bytes in buffer   */
    uint32_t       wire_len; /* bytes on the wire */
} BpfPkt;

/* ── BPF opcode classes ────────────────────────────────────────────────────── */
#define BPF_CLASS(c) ((c) & 0x07u)
#define BPF_LD   0x00u
#define BPF_LDX  0x01u
#define BPF_ST   0x02u
#define BPF_STX  0x03u
#define BPF_ALU  0x04u
#define BPF_JMP  0x05u
#define BPF_RET  0x06u
#define BPF_MISC 0x07u

#define BPF_SIZE(c) ((c) & 0x18u)
#define BPF_W 0x00u
#define BPF_H 0x08u
#define BPF_B 0x10u

#define BPF_MODE(c) ((c) & 0xe0u)
#define BPF_IMM 0x00u
#define BPF_ABS 0x20u
#define BPF_IND 0x40u
#define BPF_MEM 0x60u
#define BPF_LEN 0x80u
#define BPF_MSH 0xa0u

#define BPF_OP(c)  ((c) & 0xf0u)
#define BPF_ADD 0x00u
#define BPF_SUB 0x10u
#define BPF_MUL 0x20u
#define BPF_DIV 0x30u
#define BPF_OR  0x40u
#define BPF_AND 0x50u
#define BPF_LSH 0x60u
#define BPF_RSH 0x70u
#define BPF_NEG 0x80u
#define BPF_XOR 0xa0u

#define BPF_SRC(c) ((c) & 0x08u)
#define BPF_K 0x00u
#define BPF_X 0x08u

#define BPF_JEQ  0x10u
#define BPF_JGT  0x20u
#define BPF_JGE  0x30u
#define BPF_JSET 0x40u

#define BPF_RVAL(c) ((c) & 0x18u)
#define BPF_A  0x10u

/* ── Public API ────────────────────────────────────────────────────────────── */

/* Execute prog against pkt; returns bytes to accept (0 = drop). */
uint32_t bpf_exec(const BpfProg *prog, const BpfPkt *pkt);

/* Validate that prog has no out-of-bounds jumps and ends with RET.
 * Returns true if safe to execute. */
bool bpf_validate(const BpfProg *prog);

/* Simple read-only BPF scratch memory for use by bpf_exec. */
#define BPF_MEMWORDS 16u
