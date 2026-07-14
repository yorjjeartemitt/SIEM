#include "net_proto_udp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UdpHeader;
#pragma pack(pop)

static AppProto udp_proto_by_port(uint16_t port) {
    switch (port) {
        case 53:              return APP_PROTO_DNS;
        case 67:  case 68:    return APP_PROTO_DHCP;
        case 161: case 162:   return APP_PROTO_SNMP;
        default:               return APP_PROTO_UNKNOWN;
    }
}
#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DnsHeader;
#pragma pack(pop)

static uint32_t dns_read_name(const unsigned char *msg, uint32_t msg_len, uint32_t offset,char *out, size_t outlen) {
    size_t o = 0;
    out[0] = '\0';
    int jumps = 0;
    uint32_t pos = offset;
    uint32_t first_pos_after = (uint32_t)-1;

    while (pos < msg_len) {
        uint8_t len_byte = msg[pos];
        if (len_byte == 0x00) {
            pos++;
            if (first_pos_after == (uint32_t)-1) first_pos_after = pos;
            break;
        }
        if ((len_byte & 0xC0) == 0xC0) { 
            if (pos + 1 >= msg_len) return (uint32_t)-1;
            if (first_pos_after == (uint32_t)-1) first_pos_after = pos + 2;
            uint16_t ptr = ((len_byte & 0x3F) << 8) | msg[pos + 1];
            if (++jumps > 20) return (uint32_t)-1;
            pos = ptr;
            continue;
        }
        uint32_t label_len = len_byte;
        pos++;
        if (pos + label_len > msg_len) return (uint32_t)-1;
        if (o != 0 && o + 1 < outlen) out[o++] = '.';
        for (uint32_t i = 0; i < label_len && o + 1 < outlen; i++) out[o++] = (char)msg[pos + i];
        pos += label_len;
    }
    out[o < outlen ? o : outlen - 1] = '\0';
    return first_pos_after;
}

static const char *dns_qtype_name(uint16_t t) {
    switch (t) {
        case 1:   return "A";
        case 2:   return "NS";
        case 5:   return "CNAME";
        case 6:   return "SOA";
        case 12:  return "PTR";
        case 15:  return "MX";
        case 16:  return "TXT";
        case 28:  return "AAAA";
        case 33:  return "SRV";
        case 255: return "ANY";
        default:  return "?";
    }
}

static void parse_dns(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_DNS;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "DNS");

    if (len < sizeof(DnsHeader)) {
        snprintf(pkt->info, sizeof(pkt->info), "truncated DNS message");
        return;
    }
    const DnsHeader *h = (const DnsHeader *)data;
    uint16_t flags = ntohs(h->flags);
    int is_response = (flags >> 15) & 0x1;
    uint8_t rcode = flags & 0x0F;
    uint16_t qdcount = ntohs(h->qdcount);
    uint16_t ancount = ntohs(h->ancount);

    if (qdcount == 0) {
        snprintf(pkt->info, sizeof(pkt->info), "DNS %s (id=%u, no questions)",
                 is_response ? "response" : "query", ntohs(h->id));
        return;
    }
    char qname[192];
    uint32_t pos = dns_read_name(data, len, sizeof(DnsHeader), qname, sizeof(qname));
    if (pos == (uint32_t)-1 || pos + 4 > len) {
        snprintf(pkt->info, sizeof(pkt->info), "DNS %s (id=%u, malformed question)",
                 is_response ? "response" : "query", ntohs(h->id));
        return;
    }
    uint16_t qtype = (data[pos] << 8) | data[pos + 1];

    if (!is_response) {
        snprintf(pkt->info, sizeof(pkt->info), "DNS query: %s %s (id=%u)",
                 dns_qtype_name(qtype), qname, ntohs(h->id));
        return;
    }

    if (rcode != 0) {
        static const char *rcode_names[] = {
            "NoError","FormErr","ServFail","NXDomain","NotImp","Refused"
        };
        const char *rn = (rcode < 6) ? rcode_names[rcode] : "Err?";
        snprintf(pkt->info, sizeof(pkt->info), "DNS response: %s %s -> %s (id=%u)",
                 dns_qtype_name(qtype), qname, rn, ntohs(h->id));
        return;
    }
    pos += 4;
    char first_answer[128] = "";
    if (ancount > 0 && pos < len) {
        char aname[192];
        uint32_t apos = dns_read_name(data, len, pos, aname, sizeof(aname));
        if (apos != (uint32_t)-1 && apos + 10 <= len) {
            uint16_t atype = (data[apos] << 8) | data[apos + 1];
            uint16_t rdlen  = (data[apos + 8] << 8) | data[apos + 9];
            uint32_t rdata_off = apos + 10;
            if (atype == 1 && rdlen == 4 && rdata_off + 4 <= len) {
                struct in_addr a;
                memcpy(&a, data + rdata_off, 4);
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
                snprintf(first_answer, sizeof(first_answer), " -> %s", ipstr);
            } else if (atype == 28 && rdlen == 16 && rdata_off + 16 <= len) {
                char ipstr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, data + rdata_off, ipstr, sizeof(ipstr));
                snprintf(first_answer, sizeof(first_answer), " -> %s", ipstr);
            } else if (atype == 5 && rdata_off < len) {
                char cname[192];
                if (dns_read_name(data, len, rdata_off, cname, sizeof(cname)) != (uint32_t)-1)
                    snprintf(first_answer, sizeof(first_answer), " -> CNAME %.100s", cname);
            }
        }
    }

    snprintf(pkt->info, sizeof(pkt->info), "DNS response: %s %s%s (id=%u, %u answers)",
             dns_qtype_name(qtype), qname, first_answer, ntohs(h->id), ancount);
}
static const char *dhcp_msgtype_name(uint8_t t) {
    switch (t) {
        case 1: return "DISCOVER";
        case 2: return "OFFER";
        case 3: return "REQUEST";
        case 4: return "DECLINE";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "RELEASE";
        case 8: return "INFORM";
        default: return "?";
    }
}

static void parse_dhcp(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_DHCP;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "DHCP");

    if (len < 240) {
        snprintf(pkt->info, sizeof(pkt->info), "DHCP/BOOTP truncated segment (%u bytes)", len);
        return;
    }
    uint8_t op = data[0];
    struct in_addr ciaddr, yiaddr;
    memcpy(&ciaddr, data + 12, 4);
    memcpy(&yiaddr, data + 16, 4);

    static const unsigned char cookie[4] = {0x63, 0x82, 0x53, 0x63};
    if (memcmp(data + 236, cookie, 4) != 0) {
        snprintf(pkt->info, sizeof(pkt->info), "BOOTP %s (no DHCP options)",
                 op == 1 ? "request" : "reply");
        return;
    }

    unsigned int pos = 240;
    uint8_t msg_type = 0;
    while (pos < len) {
        uint8_t opt = data[pos];
        if (opt == 0xFF) break;
        if (opt == 0x00) { pos++; continue; }
        if (pos + 1 >= len) break;
        uint8_t opt_len = data[pos + 1];
        if (pos + 2 + opt_len > len) break;
        if (opt == 53 && opt_len == 1) msg_type = data[pos + 2];
        pos += 2 + opt_len;
    }

    char ci[INET_ADDRSTRLEN], yi[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ciaddr, ci, sizeof(ci));
    inet_ntop(AF_INET, &yiaddr, yi, sizeof(yi));

    if (msg_type) {
        snprintf(pkt->info, sizeof(pkt->info), "DHCP %s (client=%s, your-ip=%s)",
                 dhcp_msgtype_name(msg_type), ci, yi);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "DHCP/BOOTP %s", op == 1 ? "request" : "reply");
    }
}

static int ber_read_len_local(const unsigned char *d, unsigned int len, unsigned int *pos, uint32_t *out_len) {
    if (*pos >= len) return -1;
    uint8_t first = d[*pos];
    (*pos)++;
    if (!(first & 0x80)) { *out_len = first; return 0; }
    uint8_t nbytes = first & 0x7F;
    if (nbytes == 0 || nbytes > 4 || *pos + nbytes > len) return -1;
    uint32_t v = 0;
    for (uint8_t i = 0; i < nbytes; i++) v = (v << 8) | d[*pos + i];
    *pos += nbytes;
    *out_len = v;
    return 0;
}

static const char *snmp_pdu_name(uint8_t tag) {
    switch (tag & 0x1F) {
        case 0: return "GetRequest";
        case 1: return "GetNextRequest";
        case 2: return "GetResponse";
        case 3: return "SetRequest";
        case 4: return "Trap(v1)";
        case 5: return "GetBulkRequest";
        case 6: return "InformRequest";
        case 7: return "Trapv2";
        default: return "PDU?";
    }
}

static void parse_snmp(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_SNMP;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "SNMP");

    if (len < 8 || data[0] != 0x30) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP segment (%u bytes)", len);
        return;
    }
    unsigned int pos = 1;
    uint32_t seq_len;
    if (ber_read_len_local(data, len, &pos, &seq_len) < 0) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP malformed BER");
        return;
    }
    if (pos >= len || data[pos] != 0x02) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP message (bad version tag)");
        return;
    }
    pos++;
    uint32_t ver_len;
    if (ber_read_len_local(data, len, &pos, &ver_len) < 0 || pos + ver_len > len) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP malformed version");
        return;
    }
    uint8_t version = ver_len == 1 ? data[pos] : 0;
    pos += ver_len;
    if (pos >= len || data[pos] != 0x04) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP v%s message (no community string)",
                 version == 0 ? "1" : version == 1 ? "2c" : "3");
        return;
    }
    pos++;
    uint32_t comm_len;
    if (ber_read_len_local(data, len, &pos, &comm_len) < 0 || pos + comm_len > len) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP malformed community string");
        return;
    }
    char community[64];
    uint32_t clen = comm_len < sizeof(community) - 1 ? comm_len : sizeof(community) - 1;
    memcpy(community, data + pos, clen);
    community[clen] = '\0';
    pos += comm_len;

    const char *ver_name = version == 0 ? "v1" : version == 1 ? "v2c" : "v3";

    if (pos >= len) {
        snprintf(pkt->info, sizeof(pkt->info), "SNMP %s (community=%s)", ver_name, community);
        return;
    }
    uint8_t pdu_tag = data[pos];
    snprintf(pkt->info, sizeof(pkt->info), "SNMP %s %s (community=%s)",
             ver_name, snmp_pdu_name(pdu_tag), community);

    snprintf(pkt->alert_reason, sizeof(pkt->alert_reason),
             "SNMP %s community string sent in cleartext", ver_name);
    pkt->is_alert = 1;
}
void net_proto_parse_udp(const unsigned char *payload, unsigned int payload_len, NetPacket *pkt) {
    pkt->proto_str[0] = '\0';
    pkt->info[0] = '\0';

    if (payload_len < sizeof(UdpHeader)) {
        snprintf(pkt->proto_str, sizeof(pkt->proto_str), "UDP");
        snprintf(pkt->info, sizeof(pkt->info), "truncated UDP segment");
        return;
    }

    const UdpHeader *udp = (const UdpHeader *)payload;
    pkt->src_port = ntohs(udp->src_port);
    pkt->dst_port = ntohs(udp->dst_port);

    const unsigned char *app_data = payload + sizeof(UdpHeader);
    unsigned int app_len = payload_len - sizeof(UdpHeader);

    if (app_len == 0) {
        pkt->proto = APP_PROTO_UDP;
        snprintf(pkt->proto_str, sizeof(pkt->proto_str), "UDP");
        snprintf(pkt->info, sizeof(pkt->info), "%u -> %u (empty datagram)", pkt->src_port, pkt->dst_port);
        return;
    }

    AppProto proto = udp_proto_by_port(pkt->dst_port);
    if (proto == APP_PROTO_UNKNOWN) proto = udp_proto_by_port(pkt->src_port);

    switch (proto) {
        case APP_PROTO_DNS:  parse_dns(app_data, app_len, pkt); break;
        case APP_PROTO_DHCP: parse_dhcp(app_data, app_len, pkt); break;
        case APP_PROTO_SNMP: parse_snmp(app_data, app_len, pkt); break;
        default:
            pkt->proto = APP_PROTO_UDP;
            snprintf(pkt->proto_str, sizeof(pkt->proto_str), "UDP");
            snprintf(pkt->info, sizeof(pkt->info), "%u -> %u, %u bytes payload",
                     pkt->src_port, pkt->dst_port, app_len);
            break;
    }
}