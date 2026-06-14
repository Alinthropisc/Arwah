#include "proto.h"
#include <string.h>

size_t proto_parse_eth(const uint8_t *pkt, size_t len, EthHdr *out) {
    if (len < ETH_HLEN) return 0;
    memcpy(out->dst, pkt,     6);
    memcpy(out->src, pkt + 6, 6);

    uint16_t et = (uint16_t)((pkt[12] << 8) | pkt[13]);
    size_t consumed = ETH_HLEN;
    out->vlan_id = 0;

    /* Strip 802.1Q / QinQ VLAN tags. */
    while (et == ETH_TYPE_VLAN || et == ETH_TYPE_QINQ) {
        if (consumed + 4 > len) return 0;
        out->vlan_id = (uint16_t)(((pkt[consumed] & 0x0Fu) << 8) | pkt[consumed + 1]);
        et = (uint16_t)((pkt[consumed + 2] << 8) | pkt[consumed + 3]);
        consumed += 4;
    }

    out->ethertype = et;
    return consumed;
}
