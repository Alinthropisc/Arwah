/* Classic BPF interpreter — IEEE 1003.1 / BSD packet filter ISA.
 *
 * The kernel handles BPF for live captures (via libpcap); this software
 * fallback is used for PCAP-file replay, unit tests, and the display-filter
 * preview path where kernel BPF is unavailable. */

#include "bpf.h"
#include <string.h>
#include <assert.h>

/* Safely load N bytes starting at offset off from pkt.
 * Returns 0 and sets *ok=false on out-of-bounds access. */
static uint32_t pkt_load(const BpfPkt *pkt, uint32_t off, uint8_t n, bool *ok) {
    if (off + n > pkt->cap_len) { *ok = false; return 0; }
    const uint8_t *p = pkt->data + off;
    switch (n) {
    case 4: return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                 | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
    case 2: return ((uint32_t)p[0] <<  8) |  (uint32_t)p[1];
    case 1: return p[0];
    }
    *ok = false;
    return 0;
}

uint32_t bpf_exec(const BpfProg *prog, const BpfPkt *pkt) {
    assert(prog && pkt);
    if (!prog->insns || prog->len == 0) return 0;

    uint32_t A = 0, X = 0;
    uint32_t mem[BPF_MEMWORDS] = {0};
    bool ok = true;

    for (size_t pc = 0; pc < prog->len && ok; ++pc) {
        const BpfInsn *i = &prog->insns[pc];

        switch (BPF_CLASS(i->code)) {

        case BPF_LD:
            switch (BPF_MODE(i->code)) {
            case BPF_ABS: {
                uint8_t sz = (BPF_SIZE(i->code) == BPF_W) ? 4
                           : (BPF_SIZE(i->code) == BPF_H) ? 2 : 1;
                A = pkt_load(pkt, i->k, sz, &ok);
                break;
            }
            case BPF_IND: {
                uint8_t sz = (BPF_SIZE(i->code) == BPF_W) ? 4
                           : (BPF_SIZE(i->code) == BPF_H) ? 2 : 1;
                A = pkt_load(pkt, X + i->k, sz, &ok);
                break;
            }
            case BPF_IMM: A = i->k; break;
            case BPF_MEM: A = (i->k < BPF_MEMWORDS) ? mem[i->k] : 0; break;
            case BPF_LEN: A = pkt->wire_len; break;
            case BPF_MSH: {
                uint8_t b = (uint8_t)pkt_load(pkt, i->k, 1, &ok);
                X = (uint32_t)(b & 0x0Fu) << 2;
                break;
            }
            }
            break;

        case BPF_LDX:
            switch (BPF_MODE(i->code)) {
            case BPF_IMM: X = i->k; break;
            case BPF_MEM: X = (i->k < BPF_MEMWORDS) ? mem[i->k] : 0; break;
            case BPF_LEN: X = pkt->wire_len; break;
            case BPF_MSH: {
                uint8_t b = (uint8_t)pkt_load(pkt, i->k, 1, &ok);
                X = (uint32_t)(b & 0x0Fu) << 2;
                break;
            }
            }
            break;

        case BPF_ALU: {
            uint32_t src = (BPF_SRC(i->code) == BPF_K) ? i->k : X;
            switch (BPF_OP(i->code)) {
            case BPF_ADD: A += src;  break;
            case BPF_SUB: A -= src;  break;
            case BPF_MUL: A *= src;  break;
            case BPF_DIV: if (src == 0) return 0; A /= src; break;
            case BPF_OR:  A |= src;  break;
            case BPF_AND: A &= src;  break;
            case BPF_LSH: A <<= (src & 31u); break;
            case BPF_RSH: A >>= (src & 31u); break;
            case BPF_NEG: A = ~A;    break;
            case BPF_XOR: A ^= src;  break;
            }
            break;
        }

        case BPF_JMP: {
            uint32_t src = (BPF_SRC(i->code) == BPF_K) ? i->k : X;
            bool branch = false;
            switch (BPF_OP(i->code)) {
            case BPF_JEQ:  branch = (A == src);      break;
            case BPF_JGT:  branch = (A >  src);      break;
            case BPF_JGE:  branch = (A >= src);      break;
            case BPF_JSET: branch = (A & src) != 0u; break;
            default: break;
            }
            pc += branch ? i->jt : i->jf;
            break;
        }

        case BPF_RET:
            return (BPF_RVAL(i->code) == BPF_A) ? A : i->k;

        case BPF_ST:
            if (i->k < BPF_MEMWORDS) mem[i->k] = A;
            break;

        case BPF_STX:
            if (i->k < BPF_MEMWORDS) mem[i->k] = X;
            break;

        case BPF_MISC:
            /* TAX: A → X, TXA: X → A */
            if ((i->code & 0xf8u) == 0x00u) X = A; else A = X;
            break;
        }
    }

    return 0; /* no RET reached — reject */
}

bool bpf_validate(const BpfProg *prog) {
    if (!prog || !prog->insns || prog->len == 0) return false;
    /* Last instruction must be a RET. */
    const BpfInsn *last = &prog->insns[prog->len - 1];
    if (BPF_CLASS(last->code) != BPF_RET) return false;
    /* All jump targets must be in-bounds. */
    for (size_t pc = 0; pc < prog->len; ++pc) {
        const BpfInsn *i = &prog->insns[pc];
        if (BPF_CLASS(i->code) == BPF_JMP) {
            if (pc + 1 + i->jt >= prog->len) return false;
            if (pc + 1 + i->jf >= prog->len) return false;
        }
    }
    return true;
}
