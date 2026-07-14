#ifndef NET_PROTO_UDP_H
#define NET_PROTO_UDP_H

#include "net_capture.h"

void net_proto_parse_udp(const unsigned char *payload, unsigned int payload_len,
                          NetPacket *pkt);

#endif