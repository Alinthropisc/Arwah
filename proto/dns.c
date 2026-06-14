/* DNS header + first question dissector.
 *
 * Handles compressed labels (pointer chains, RFC 1035 §4.1.4).
 * Max pointer chain depth is bounded to prevent infinite loops. */

#include "proto.h"
#include <string.h>
#include <stdio.h>

#define MAX_PTR_DEPTH 10u

/* Decode a DNS name starting at pkt[off] into buf (buf_len bytes including NUL).
 * Returns the offset AFTER the name's terminator in the current section
 * (NOT after any pointer target), so the caller can advance correctly.
 * Returns 0 on failure. */
static size_t dns_decode_name(
    const uint8_t *pkt, size_t pkt_len,
    size_t off,
    char *buf, size_t buf_len)
{
    size_t pos = 0;
    size_t first_after = 0;   /* offset to return (first non-pointer step) */
    bool   seen_ptr   = false;
    unsigned depth = 0;

    while (off < pkt_len) {
        uint8_t label_len = pkt[off];

        if ((label_len & 0xC0u) == 0xC0u) {
            /* Pointer */
            if (off + 1 >= pkt_len) return 0;
            if (!seen_ptr) { first_after = off + 2; seen_ptr = true; }
            off = (size_t)(((label_len & 0x3Fu) << 8) | pkt[off + 1]);
            if (++depth > MAX_PTR_DEPTH) return 0;
            continue;
        }

        if (label_len == 0) {
            /* Root label — name is complete. */
            if (!seen_ptr) first_after = off + 1;
            if (pos > 0 && buf[pos - 1] == '.') buf[pos - 1] = '\0';
            else if (pos < buf_len) buf[pos] = '\0';
            return first_after;
        }

        ++off;
        if (off + label_len > pkt_len) return 0;
        if (pos + label_len + 1 >= buf_len) return 0; /* overflow guard */

        memcpy(buf + pos, pkt + off, label_len);
        pos     += label_len;
        buf[pos++] = '.';
        off     += label_len;
    }
    return 0;
}

size_t proto_parse_dns(
    const uint8_t *pkt, size_t len,
    DnsHdr *hdr, DnsQuestion *q)
{
    if (len < 12) return 0;

    hdr->id      = (uint16_t)((pkt[0] << 8) | pkt[1]);
    hdr->qr      = (pkt[2] >> 7) & 1u;
    hdr->opcode  = (pkt[2] >> 3) & 0x0Fu;
    hdr->aa      = (pkt[2] >> 2) & 1u;
    hdr->tc      = (pkt[2] >> 1) & 1u;
    hdr->rd      = pkt[2] & 1u;
    hdr->ra      = (pkt[3] >> 7) & 1u;
    hdr->rcode   = pkt[3] & 0x0Fu;
    hdr->qdcount = (uint16_t)((pkt[4]  << 8) | pkt[5]);
    hdr->ancount = (uint16_t)((pkt[6]  << 8) | pkt[7]);
    hdr->nscount = (uint16_t)((pkt[8]  << 8) | pkt[9]);
    hdr->arcount = (uint16_t)((pkt[10] << 8) | pkt[11]);

    if (!q || hdr->qdcount == 0) return 12;

    /* Parse first question. */
    memset(q, 0, sizeof(*q));
    size_t off = dns_decode_name(pkt, len, 12, q->name, sizeof(q->name));
    if (!off || off + 4 > len) return 12;

    q->qtype  = (uint16_t)((pkt[off]   << 8) | pkt[off + 1]);
    q->qclass = (uint16_t)((pkt[off+2] << 8) | pkt[off + 3]);
    return 12; /* return header size; caller can inspect q independently */
}
