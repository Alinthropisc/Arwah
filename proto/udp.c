#include "proto.h"

size_t proto_parse_udp(const uint8_t *pkt, size_t len, UdpHdr *out) {
    if (len < 8) return 0;
    out->src_port = (uint16_t)((pkt[0] << 8) | pkt[1]);
    out->dst_port = (uint16_t)((pkt[2] << 8) | pkt[3]);
    out->length   = (uint16_t)((pkt[4] << 8) | pkt[5]);
    out->checksum = (uint16_t)((pkt[6] << 8) | pkt[7]);
    return 8;
}
