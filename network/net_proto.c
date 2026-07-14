#include "net_proto.h"
#include "net_proto_tcp.h"
#include "net_proto_udp.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} EthHeader;

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_8021Q 0x8100

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPv4Header;

typedef struct {
    uint32_t ver_class_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
} IPv6Header;

#pragma pack(pop)

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17
#define IP_PROTO_ICMPV6 58
#pragma pack(push, 1)
typedef struct {
    uint16_t packet_type;
    uint16_t arphrd_type;
    uint16_t link_addr_len;
    uint8_t  link_addr[8];
    uint16_t protocol;
} SllHeader;
#pragma pack(pop)

static void ipv4_to_str(uint32_t ip_be, char *out, size_t outlen) {
    struct in_addr a;
    a.s_addr = ip_be;
    inet_ntop(AF_INET, &a, out, outlen);
}

static void ipv6_to_str(const uint8_t *ip, char *out, size_t outlen) {
    inet_ntop(AF_INET6, ip, out, outlen);
}

#pragma pack(push, 1)
typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
} ArpHeader;
#pragma pack(pop)

static void parse_arp(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "ARP");
    pkt->proto = APP_PROTO_ARP;
    if (len < sizeof(ArpHeader)) {
        snprintf(pkt->info, sizeof(pkt->info), "truncated ARP packet");
        return;
    }
    const ArpHeader *arp = (const ArpHeader *)data;
    char spa[16], tpa[16];
    struct in_addr a;
    memcpy(&a, arp->spa, 4); inet_ntop(AF_INET, &a, spa, sizeof(spa));
    memcpy(&a, arp->tpa, 4); inet_ntop(AF_INET, &a, tpa, sizeof(tpa));

    snprintf(pkt->src_ip, sizeof(pkt->src_ip), "%s", spa);
    snprintf(pkt->dst_ip, sizeof(pkt->dst_ip), "%s", tpa);

    uint16_t oper = ntohs(arp->oper);
    snprintf(pkt->info, sizeof(pkt->info), "%s: who has %s? tell %s",
             oper == 1 ? "Request" : (oper == 2 ? "Reply" : "Op?"), tpa, spa);
}
static void dispatch_transport(uint8_t ip_proto, const unsigned char *l4, unsigned int l4_len,
                                NetPacket *pkt) {
    switch (ip_proto) {
        case IP_PROTO_TCP:
            net_proto_parse_tcp(l4, l4_len, pkt);
            break;
        case IP_PROTO_UDP:
            net_proto_parse_udp(l4, l4_len, pkt);
            break;
        case IP_PROTO_ICMP:
        case IP_PROTO_ICMPV6:
            pkt->proto = APP_PROTO_ICMP;
            snprintf(pkt->proto_str, sizeof(pkt->proto_str), "ICMP");
            snprintf(pkt->info, sizeof(pkt->info), "ICMP message (%u bytes)", l4_len);
            break;
        default:
            pkt->proto = APP_PROTO_UNKNOWN;
            snprintf(pkt->proto_str, sizeof(pkt->proto_str), "IP-%u", ip_proto);
            snprintf(pkt->info, sizeof(pkt->info), "unhandled IP protocol %u", ip_proto);
            break;
    }
}

static int parse_ipv4(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    if (len < sizeof(IPv4Header)) return -1;
    const IPv4Header *ip = (const IPv4Header *)data;

    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl_words = ip->ver_ihl & 0x0F;
    if (version != 4) return -1;
    uint32_t ihl_bytes = ihl_words * 4u;
    if (ihl_bytes < sizeof(IPv4Header) || ihl_bytes > len) return -1;

    ipv4_to_str(ip->src_ip, pkt->src_ip, sizeof(pkt->src_ip));
    ipv4_to_str(ip->dst_ip, pkt->dst_ip, sizeof(pkt->dst_ip));

    uint16_t total_len = ntohs(ip->total_len);
    uint32_t l4_avail = len - ihl_bytes;
    uint32_t l4_declared = (total_len > ihl_bytes) ? (uint32_t)(total_len - ihl_bytes) : 0;
    uint32_t l4_len = l4_declared < l4_avail ? l4_declared : l4_avail;

    dispatch_transport(ip->protocol, data + ihl_bytes, l4_len, pkt);
    return 0;
}

static int parse_ipv6(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    if (len < sizeof(IPv6Header)) return -1;
    const IPv6Header *ip6 = (const IPv6Header *)data;

    uint8_t version = (ntohl(ip6->ver_class_flow) >> 28) & 0xF;
    if (version != 6) return -1;

    ipv6_to_str(ip6->src_ip, pkt->src_ip, sizeof(pkt->src_ip));
    ipv6_to_str(ip6->dst_ip, pkt->dst_ip, sizeof(pkt->dst_ip));

    uint16_t payload_len = ntohs(ip6->payload_len);
    uint32_t l4_avail = len - sizeof(IPv6Header);
    uint32_t l4_len = payload_len < l4_avail ? payload_len : l4_avail;

    dispatch_transport(ip6->next_header, data + sizeof(IPv6Header), l4_len, pkt);
    return 0;
}
int net_proto_parse(const unsigned char *bytes, unsigned int caplen,
                     int datalink, NetPacket *pkt) {
    const unsigned char *l3 = NULL;
    unsigned int l3_len = 0;
    uint16_t ethertype = 0;

    if (datalink == DLT_LINUX_SLL) {
        if (caplen < sizeof(SllHeader)) return -1;
        const SllHeader *sll = (const SllHeader *)bytes;
        ethertype = ntohs(sll->protocol);
        l3 = bytes + sizeof(SllHeader);
        l3_len = caplen - sizeof(SllHeader);
    } else {
        if (caplen < sizeof(EthHeader)) return -1;
        const EthHeader *eth = (const EthHeader *)bytes;
        ethertype = ntohs(eth->ethertype);
        l3 = bytes + sizeof(EthHeader);
        l3_len = caplen - sizeof(EthHeader);
        if (ethertype == ETHERTYPE_8021Q) {
            if (l3_len < 4) return -1;
            ethertype = ntohs(*(const uint16_t *)(l3 + 2));
            l3 += 4;
            l3_len -= 4;
        }
    }
    switch (ethertype) {
        case ETHERTYPE_IPV4:
            return parse_ipv4(l3, l3_len, pkt);
        case ETHERTYPE_IPV6:
            return parse_ipv6(l3, l3_len, pkt);
        case ETHERTYPE_ARP:
            parse_arp(l3, l3_len, pkt);
            return 0;
        default:
            return -1;
    }
}

const char *net_proto_name(AppProto p) {
    switch (p) {
        case APP_PROTO_HTTP:       return "HTTP";
        case APP_PROTO_HTTPS:      return "HTTPS";
        case APP_PROTO_SMTP:       return "SMTP";
        case APP_PROTO_SMTPS:      return "SMTPS";
        case APP_PROTO_TELNET:     return "TELNET";
        case APP_PROTO_FTP:        return "FTP";
        case APP_PROTO_FTP_DATA:   return "FTP-DATA";
        case APP_PROTO_POP3:       return "POP3";
        case APP_PROTO_POP3S:      return "POP3S";
        case APP_PROTO_IMAP:       return "IMAP";
        case APP_PROTO_IMAPS:      return "IMAPS";
        case APP_PROTO_DHCP:       return "DHCP";
        case APP_PROTO_DNS:        return "DNS";
        case APP_PROTO_SNMP:       return "SNMP";
        case APP_PROTO_LDAP:       return "LDAP";
        case APP_PROTO_LDAPS:      return "LDAPS";
        case APP_PROTO_MYSQL:      return "MYSQL";
        case APP_PROTO_POSTGRESQL: return "POSTGRESQL";
        case APP_PROTO_MONGODB:    return "MONGODB";
        case APP_PROTO_SMB:        return "SMB";
        case APP_PROTO_TCP:        return "TCP";
        case APP_PROTO_UDP:        return "UDP";
        case APP_PROTO_ICMP:       return "ICMP";
        case APP_PROTO_ARP:        return "ARP";
        default:                   return "UNKNOWN";
    }
}