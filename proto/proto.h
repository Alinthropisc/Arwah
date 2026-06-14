/* B579-Arwah protocol dissector API.
 *
 * Each dissector returns the number of bytes consumed, 0 on parse failure.
 * All multi-byte integers in parsed structs are in HOST byte order.
 * Input pointers always point into the original packet buffer (zero-copy). */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>   /* in_addr, in6_addr */
#include <arpa/inet.h>    /* ntohs, ntohl       */

/* ── Ethernet ──────────────────────────────────────────────────────────────── */
#define ETH_HLEN         14u
#define ETH_TYPE_IPV4  0x0800u
#define ETH_TYPE_IPV6  0x86DDu
#define ETH_TYPE_ARP   0x0806u
#define ETH_TYPE_VLAN  0x8100u
#define ETH_TYPE_QINQ  0x88A8u

typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;   /* host order; strips 802.1Q tag if present */
    uint16_t vlan_id;     /* 0 if no VLAN tag                         */
} EthHdr;

/* ── IPv4 ──────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t       ihl;        /* header length in bytes (ihl * 4)  */
    uint8_t       dscp;
    uint8_t       ecn;
    uint16_t      total_len;
    uint16_t      id;
    bool          df;
    bool          mf;
    uint16_t      frag_off;
    uint8_t       ttl;
    uint8_t       proto;
    uint16_t      checksum;
    struct in_addr src;
    struct in_addr dst;
    bool          checksum_ok;
} Ip4Hdr;

/* ── IPv6 ──────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t       tc;
    uint32_t      flow_label;
    uint16_t      payload_len;
    uint8_t       next_hdr;
    uint8_t       hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
} Ip6Hdr;

/* ── TCP ───────────────────────────────────────────────────────────────────── */
#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u
#define TCP_FLAG_ECE 0x40u
#define TCP_FLAG_CWR 0x80u

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;  /* header length in bytes */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} TcpHdr;

/* ── UDP ───────────────────────────────────────────────────────────────────── */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UdpHdr;

/* ── ICMP ──────────────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;    /* type-specific 4-byte field */
} IcmpHdr;

/* ── DNS ───────────────────────────────────────────────────────────────────── */
#define DNS_MAX_LABELS 128u
#define DNS_NAME_MAX   253u

typedef struct {
    uint16_t id;
    bool     qr;        /* false = query, true = response */
    uint8_t  opcode;
    bool     aa, tc, rd, ra;
    uint8_t  rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DnsHdr;

typedef struct {
    char     name[DNS_NAME_MAX + 1];
    uint16_t qtype;
    uint16_t qclass;
} DnsQuestion;

/* ── TLS ───────────────────────────────────────────────────────────────────── */
#define TLS_MAX_SNI 256u

typedef struct {
    uint8_t  record_type;
    uint8_t  major_ver;
    uint8_t  minor_ver;
    uint16_t length;

    /* Populated only for ClientHello records. */
    bool     is_client_hello;
    char     sni[TLS_MAX_SNI];  /* server name from SNI extension, or "" */
    uint16_t offered_version;   /* highest TLS version offered            */
} TlsRecord;

/* ── Dissector functions ───────────────────────────────────────────────────── */

/* Returns bytes consumed (>= ETH_HLEN) or 0 on failure. */
size_t proto_parse_eth(const uint8_t *pkt, size_t len, EthHdr *out);

/* Returns bytes consumed or 0 on failure.
 * Writes checksum validation result into out->checksum_ok. */
size_t proto_parse_ip4(const uint8_t *pkt, size_t len, Ip4Hdr *out);
size_t proto_parse_ip6(const uint8_t *pkt, size_t len, Ip6Hdr *out);

size_t proto_parse_tcp (const uint8_t *pkt, size_t len, TcpHdr *out);
size_t proto_parse_udp (const uint8_t *pkt, size_t len, UdpHdr *out);
size_t proto_parse_icmp(const uint8_t *pkt, size_t len, IcmpHdr *out);

/* Parses DNS header and the first question. Returns header bytes consumed. */
size_t proto_parse_dns(const uint8_t *pkt, size_t len, DnsHdr *hdr, DnsQuestion *q);

/* Parses the first TLS record, extracting SNI from ClientHello if present. */
size_t proto_parse_tls(const uint8_t *pkt, size_t len, TlsRecord *out);

/* RFC-1071 Internet checksum. */
uint16_t proto_inet_checksum(const uint8_t *data, size_t len);
