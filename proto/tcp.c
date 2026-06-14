#include "proto.h"

size_t proto_parse_tcp(const uint8_t *pkt, size_t len, TcpHdr *out) {
    if (len < 20) return 0;
    out->src_port = (uint16_t)((pkt[0] << 8) | pkt[1]);
    out->dst_port = (uint16_t)((pkt[2] << 8) | pkt[3]);
    out->seq      = ((uint32_t)pkt[4] << 24) | ((uint32_t)pkt[5] << 16)
                  | ((uint32_t)pkt[6] <<  8) |  (uint32_t)pkt[7];
    out->ack      = ((uint32_t)pkt[8] << 24) | ((uint32_t)pkt[9] << 16)
                  | ((uint32_t)pkt[10] << 8) |  (uint32_t)pkt[11];
    uint8_t off   = (pkt[12] >> 4) & 0x0Fu;
    out->data_off = (uint8_t)(off * 4u);
    out->flags    = pkt[13];
    out->window   = (uint16_t)((pkt[14] << 8) | pkt[15]);
    out->checksum = (uint16_t)((pkt[16] << 8) | pkt[17]);
    out->urgent   = (uint16_t)((pkt[18] << 8) | pkt[19]);
    if (out->data_off < 20 || out->data_off > len) return 0;
    return out->data_off;
}
