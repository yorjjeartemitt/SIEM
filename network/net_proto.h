#ifndef NET_PROTO_H
#define NET_PROTO_H

#include "net_capture.h"
int net_proto_parse(const unsigned char *bytes, unsigned int caplen,
                     int datalink, NetPacket *pkt);

#endif