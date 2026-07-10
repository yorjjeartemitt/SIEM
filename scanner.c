#include "scanner.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define ETH_HDR_LEN 14
#define ARP_HDR_LEN 28

struct eth_header {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short ethertype;
} __attribute__((packed));

struct ipv4_header {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short id;
    unsigned short flags_frag;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_ip;
    unsigned int   dst_ip;
} __attribute__((packed));

struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   seq;
    unsigned int   ack;
    unsigned char  data_offset;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
} __attribute__((packed));

struct udp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
} __attribute__((packed));

struct arp_header {
    unsigned short htype;
    unsigned short ptype;
    unsigned char  hlen;
    unsigned char  plen;
    unsigned short oper;
    unsigned char  sha[6];
    unsigned char  spa[4];
    unsigned char  tha[6];
    unsigned char  tpa[4];
} __attribute__((packed));

#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17

static void mac_to_str(unsigned char *mac, char *out){
    snprintf(out,18,"%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

int scanner_start(const char *iface, int max_packets, void (*on_packet)(PacketInfo*)){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle){ fprintf(stderr,"%s\n",errbuf); return -1; }

    struct pcap_pkthdr header;
    const u_char *packet;
    int count=0;

    while (count<max_packets){
        packet = pcap_next(handle,&header);
        if (!packet) continue;
        if (header.caplen < ETH_HDR_LEN) continue;

        struct eth_header *eth = (struct eth_header*)packet;
        PacketInfo info;
        memset(&info,0,sizeof(info));
        mac_to_str(eth->src, info.src_mac);
        mac_to_str(eth->dst, info.dst_mac);
        info.ethertype = ntohs(eth->ethertype);
        info.len = header.len;

        if (info.ethertype == 0x0806 && header.caplen >= ETH_HDR_LEN + ARP_HDR_LEN){
            struct arp_header *arp = (struct arp_header*)(packet + ETH_HDR_LEN);
            struct in_addr spa, tpa;
            memcpy(&spa, arp->spa, 4);
            memcpy(&tpa, arp->tpa, 4);
            info.is_arp = 1;
            snprintf(info.src_ip,16,"%s",inet_ntoa(spa));
            snprintf(info.dst_ip,16,"%s",inet_ntoa(tpa));
            info.protocol = 0;
        }
        else if (info.ethertype == 0x0800 && header.caplen >= ETH_HDR_LEN + 20){
            struct ipv4_header *ip = (struct ipv4_header*)(packet + ETH_HDR_LEN);

            unsigned int ihl = (ip->ver_ihl & 0x0F) * 4;
            if (ihl < 20) { if (on_packet) on_packet(&info); count++; continue; }

            struct in_addr src, dst;
            src.s_addr = ip->src_ip;
            dst.s_addr = ip->dst_ip;
            snprintf(info.src_ip,16,"%s",inet_ntoa(src));
            snprintf(info.dst_ip,16,"%s",inet_ntoa(dst));
            info.protocol = ip->protocol;

            unsigned int l4_offset = ETH_HDR_LEN + ihl;

            if (ip->protocol == IPPROTO_TCP_ &&
                header.caplen >= l4_offset + sizeof(struct tcp_header)){
                struct tcp_header *tcp = (struct tcp_header*)(packet + l4_offset);
                info.src_port = ntohs(tcp->src_port);
                info.dst_port = ntohs(tcp->dst_port);
            }
            else if (ip->protocol == IPPROTO_UDP_ &&
                header.caplen >= l4_offset + sizeof(struct udp_header)){
                struct udp_header *udp = (struct udp_header*)(packet + l4_offset);
                info.src_port = ntohs(udp->src_port);
                info.dst_port = ntohs(udp->dst_port);
            }
        }

        if (on_packet) on_packet(&info);
        count++;
    }
    pcap_close(handle);
    return count;
}

#ifdef TEST_SCANNER
static void print_packet(PacketInfo *p){
    if (p->is_arp){
        printf("ARP  len=%d src=%s spa=%s tpa=%s\n",
            p->len, p->src_mac, p->src_ip, p->dst_ip);
    } else {
        printf("len=%d ethertype=0x%04x src=%s dst=%s proto=%d src_ip=%s:%d dst_ip=%s:%d\n",
            p->len, p->ethertype, p->src_mac, p->dst_mac, p->protocol,
            p->src_ip, p->src_port, p->dst_ip, p->dst_port);
    }
}
int main(){
    scanner_start("wlan0", 10, print_packet);
    return 0;
}
#endif