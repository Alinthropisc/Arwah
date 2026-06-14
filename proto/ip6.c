#include "proto.h"
#include <string.h>

size_t proto_parse_ip6(const uint8_t *pkt, size_t len, Ip6Hdr *out) {
    if (len < 40) return 0;

    uint32_t ver_tc_fl = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16)
                       | ((uint32_t)pkt[2] <<  8) |  (uint32_t)pkt[3];

    out->tc          = (uint8_t)((ver_tc_fl >> 20) & 0xFFu);
    out->flow_label  = ver_tc_fl & 0x000FFFFFu;
    out->payload_len = (uint16_t)((pkt[4] << 8) | pkt[5]);
    out->next_hdr    = pkt[6];
    out->hop_limit   = pkt[7];
    memcpy(&out->src, pkt +  8, 16);
    memcpy(&out->dst, pkt + 24, 16);
    return 40;
}
