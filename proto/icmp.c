#include "proto.h"

size_t proto_parse_icmp(const uint8_t *pkt, size_t len, IcmpHdr *out) {
    if (len < 8) return 0;
    out->type     = pkt[0];
    out->code     = pkt[1];
    out->checksum = (uint16_t)((pkt[2] << 8) | pkt[3]);
    out->rest     = ((uint32_t)pkt[4] << 24) | ((uint32_t)pkt[5] << 16)
                  | ((uint32_t)pkt[6] <<  8) |  (uint32_t)pkt[7];
    return 8;
}
