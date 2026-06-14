#include "proto.h"
#include <string.h>

size_t proto_parse_ip4(const uint8_t *pkt, size_t len, Ip4Hdr *out) {
    if (len < 20) return 0;
    uint8_t ihl_raw = pkt[0] & 0x0Fu;
    size_t hdr_len = (size_t)ihl_raw * 4u;
    if (hdr_len < 20 || hdr_len > len) return 0;

    out->ihl       = (uint8_t)hdr_len;
    out->dscp      = (pkt[1] >> 2) & 0x3Fu;
    out->ecn       = pkt[1] & 0x03u;
    out->total_len = (uint16_t)((pkt[2] << 8) | pkt[3]);
    out->id        = (uint16_t)((pkt[4] << 8) | pkt[5]);
    out->df        = (pkt[6] & 0x40u) != 0u;
    out->mf        = (pkt[6] & 0x20u) != 0u;
    out->frag_off  = (uint16_t)(((pkt[6] & 0x1Fu) << 8) | pkt[7]);
    out->ttl       = pkt[8];
    out->proto     = pkt[9];
    out->checksum  = (uint16_t)((pkt[10] << 8) | pkt[11]);
    memcpy(&out->src, pkt + 12, 4);
    memcpy(&out->dst, pkt + 16, 4);

    out->checksum_ok = (proto_inet_checksum(pkt, hdr_len) == 0u);
    return hdr_len;
}
