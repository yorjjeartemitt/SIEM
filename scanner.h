#ifndef SCANNER_H
#define SCANNER_H

typedef struct {
	char src_mac[18];
	char dst_mac[18];
	unsigned short ethertype;
	int len;
	char src_ip[16];
	char dst_ip[16];
	unsigned char protocol;
	unsigned short src_port;
	unsigned short dst_port;
	int is_arp;
} PacketInfo;
int scanner_start(const char *iface,int max_packets,void (*on_packet)(PacketInfo*));
#endif