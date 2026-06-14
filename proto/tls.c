/* TLS record layer parser with ClientHello SNI extraction.
 *
 * Reference: RFC 8446 §4.1.2 (TLS 1.3), RFC 5246 §7.4.1 (TLS 1.2),
 *            RFC 6066 §3 (SNI extension).
 *
 * This is a passive read-only parser — it never modifies the packet buffer. */

#include "proto.h"
#include <string.h>

/* TLS record types */
#define TLS_CHANGE_CIPHER  20u
#define TLS_ALERT          21u
#define TLS_HANDSHAKE      22u
#define TLS_APP_DATA       23u

/* Handshake message types */
#define TLS_HS_CLIENT_HELLO 1u
#define TLS_HS_SERVER_HELLO 2u

/* Extension types */
#define TLS_EXT_SNI                0x0000u
#define TLS_EXT_SUPPORTED_VERSIONS 0x002Bu

/* Safe 2-byte big-endian read. */
static inline uint16_t r16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
/* Safe 3-byte big-endian read. */
static inline uint32_t r24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* Parse SNI from TLS ClientHello extensions.
 * ext points to the start of the extensions list (after session id / cipher),
 * ext_len is the remaining bytes available. */
static void parse_extensions(
    const uint8_t *ext, size_t ext_len,
    TlsRecord *out)
{
    if (ext_len < 2) return;
    size_t total = r16(ext);
    size_t off   = 2;
    if (off + total > ext_len) return;

    while (off + 4 <= 2 + total) {
        uint16_t ext_type = r16(ext + off);
        uint16_t ext_data_len = r16(ext + off + 2);
        off += 4;
        if (off + ext_data_len > 2 + total) break;

        if (ext_type == TLS_EXT_SNI && ext_data_len >= 5) {
            /* SNI list length (2 bytes) → name type (1) → name length (2) → name */
            const uint8_t *sni_data = ext + off;
            if (sni_data[2] == 0x00u) { /* host_name type */
                uint16_t name_len = r16(sni_data + 3);
                if (name_len < TLS_MAX_SNI && 5 + name_len <= ext_data_len) {
                    memcpy(out->sni, sni_data + 5, name_len);
                    out->sni[name_len] = '\0';
                }
            }
        } else if (ext_type == TLS_EXT_SUPPORTED_VERSIONS && ext_data_len >= 2) {
            /* For TLS 1.3 ClientHello: list of offered versions. */
            const uint8_t *vdata = ext + off;
            uint8_t vlist_len = vdata[0];
            for (uint8_t vi = 1; vi + 1 < vlist_len && vi < ext_data_len; vi += 2) {
                uint16_t v = r16(vdata + vi);
                if (v > out->offered_version) out->offered_version = v;
            }
        }

        off += ext_data_len;
    }
}

size_t proto_parse_tls(const uint8_t *pkt, size_t len, TlsRecord *out) {
    /* Minimum TLS record header: type(1) + version(2) + length(2) = 5 bytes. */
    if (len < 5) return 0;

    out->record_type      = pkt[0];
    out->major_ver        = pkt[1];
    out->minor_ver        = pkt[2];
    out->length           = r16(pkt + 3);
    out->is_client_hello  = false;
    out->sni[0]           = '\0';
    out->offered_version  = 0;

    /* Sanity: length must fit in remaining buffer. */
    if (5u + out->length > len) return 0;

    if (out->record_type != TLS_HANDSHAKE) return 5;

    /* Parse handshake layer. */
    const uint8_t *hs = pkt + 5;
    size_t hs_len = out->length;
    if (hs_len < 4) return 5;

    if (hs[0] != TLS_HS_CLIENT_HELLO) return 5;

    uint32_t msg_len = r24(hs + 1);
    if (4 + msg_len > hs_len) return 5;

    out->is_client_hello = true;

    /* ClientHello body: version(2) + random(32) + session_id_len(1) + … */
    const uint8_t *body = hs + 4;
    size_t body_len = msg_len;
    size_t cur = 0;

    if (cur + 34 > body_len) return 5; /* version + random */
    cur += 34;

    /* Session ID */
    if (cur >= body_len) return 5;
    uint8_t sid_len = body[cur++];
    if (cur + sid_len > body_len) return 5;
    cur += sid_len;

    /* Cipher suites */
    if (cur + 2 > body_len) return 5;
    uint16_t cs_len = r16(body + cur); cur += 2;
    if (cur + cs_len > body_len) return 5;
    cur += cs_len;

    /* Compression methods */
    if (cur >= body_len) return 5;
    uint8_t comp_len = body[cur++];
    if (cur + comp_len > body_len) return 5;
    cur += comp_len;

    /* Extensions */
    if (cur < body_len) {
        parse_extensions(body + cur, body_len - cur, out);
    }

    return 5; /* record header consumed */
}
