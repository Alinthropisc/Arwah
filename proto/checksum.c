#include "proto.h"

uint16_t proto_inet_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((data[0] << 8) | data[1]);
        data += 2;
        len  -= 2;
    }
    if (len == 1) sum += (uint32_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}
