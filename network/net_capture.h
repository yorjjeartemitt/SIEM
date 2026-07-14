#ifndef NET_CAPTURE_H
#define NET_CAPTURE_H

#include <stdint.h>
#include <stddef.h>
#include <pcap/pcap.h>

#define NET_MAX_INFO      256
#define NET_MAX_IP_STR     46
#define NET_MAX_PROTO_STR  12
#define NET_MAX_TS         32
typedef enum {
    APP_PROTO_UNKNOWN = 0,
    APP_PROTO_HTTP,
    APP_PROTO_HTTPS,
    APP_PROTO_SMTP,
    APP_PROTO_SMTPS,
    APP_PROTO_TELNET,
    APP_PROTO_FTP,
    APP_PROTO_FTP_DATA,
    APP_PROTO_POP3,
    APP_PROTO_POP3S,
    APP_PROTO_IMAP,
    APP_PROTO_IMAPS,
    APP_PROTO_DHCP,
    APP_PROTO_DNS,
    APP_PROTO_SNMP,
    APP_PROTO_LDAP,
    APP_PROTO_LDAPS,
    APP_PROTO_MYSQL,
    APP_PROTO_POSTGRESQL,
    APP_PROTO_MONGODB,
    APP_PROTO_SMB,
    APP_PROTO_TCP,
    APP_PROTO_UDP,
    APP_PROTO_ICMP,
    APP_PROTO_ARP,
    APP_PROTO_COUNT
} AppProto;

const char *net_proto_name(AppProto p);
typedef struct {
    char     timestamp[NET_MAX_TS];
    char     src_ip[NET_MAX_IP_STR];
    char     dst_ip[NET_MAX_IP_STR];
    uint16_t src_port;
    uint16_t dst_port;
    AppProto proto;
    char     proto_str[NET_MAX_PROTO_STR];
    char     info[NET_MAX_INFO];
    uint32_t length;
    uint8_t  is_alert;
    char     alert_reason[64];
} NetPacket;
typedef void (*NetPacketCallback)(const NetPacket *pkt, void *user_data);
typedef struct NetCapture NetCapture;

typedef struct {
    char name[64];
    char description[256];
} NetIfaceInfo;

int net_list_interfaces(NetIfaceInfo *out, int max_count, char *errbuf);
NetCapture *net_capture_open_live(const char *iface, int promisc, int snaplen,const char *bpf_filter, char *errbuf);
NetCapture *net_capture_open_offline(const char *filepath, char *errbuf);
int net_capture_poll(NetCapture *cap, int max_packets,NetPacketCallback cb, void *user_data);
int net_capture_get_fd(NetCapture *cap);
void net_capture_close(NetCapture *cap);
typedef struct {
    unsigned long recv;
    unsigned long dropped_kernel;
    unsigned long dropped_iface;
} NetCaptureStats;

int net_capture_get_stats(NetCapture *cap, NetCaptureStats *out);

#endif