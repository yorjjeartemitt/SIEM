#ifndef NET_PROTO_TCP_H
#define NET_PROTO_TCP_H

#include "net_capture.h"
void net_proto_parse_tcp(const unsigned char *payload, unsigned int payload_len,
                          NetPacket *pkt);

#endif