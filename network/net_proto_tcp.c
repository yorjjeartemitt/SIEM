#include "net_proto_tcp.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TcpHeader;
#pragma pack(pop)

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

static AppProto proto_by_port(uint16_t port) {
    switch (port) {
        case 80:   case 8080: return APP_PROTO_HTTP;
        case 443:              return APP_PROTO_HTTPS;
        case 25:   case 587:  return APP_PROTO_SMTP;
        case 465:              return APP_PROTO_SMTPS;
        case 23:               return APP_PROTO_TELNET;
        case 21:               return APP_PROTO_FTP;
        case 20:               return APP_PROTO_FTP_DATA;
        case 110:              return APP_PROTO_POP3;
        case 995:              return APP_PROTO_POP3S;
        case 143:              return APP_PROTO_IMAP;
        case 993:              return APP_PROTO_IMAPS;
        case 389:              return APP_PROTO_LDAP;
        case 636:              return APP_PROTO_LDAPS;
        case 3306:             return APP_PROTO_MYSQL;
        case 5432:             return APP_PROTO_POSTGRESQL;
        case 27017: case 27018: case 27019: return APP_PROTO_MONGODB;
        case 445:   case 139:  return APP_PROTO_SMB;
        default:                return APP_PROTO_UNKNOWN;
    }
}
static void snprint_clean_line(char *out, size_t outlen, const unsigned char *data, unsigned int len) {
    size_t o = 0;
    for (unsigned int i = 0; i < len && o + 1 < outlen; i++) {
        unsigned char c = data[i];
        if (c == '\r' || c == '\n') break;
        out[o++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    out[o] = '\0';
}
static int looks_like_http_request(const unsigned char *d, unsigned int len) {
    static const char *methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                                     "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};
    for (size_t i = 0; i < sizeof(methods)/sizeof(methods[0]); i++) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && memcmp(d, methods[i], mlen) == 0) return 1;
    }
    return 0;
}

static int looks_like_http_response(const unsigned char *d, unsigned int len) {
    return (len >= 5 && memcmp(d, "HTTP/", 5) == 0);
}

static void parse_http(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_HTTP;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "HTTP");

    char line[200];
    snprint_clean_line(line, sizeof(line), data, len);

    if (looks_like_http_request(data, len)) {
        char host[128] = "";
        const unsigned char *p = data;
        unsigned int remaining = len;
        while (remaining > 6) {
            const unsigned char *nl = memchr(p, '\n', remaining);
            unsigned int linelen = nl ? (unsigned int)(nl - p) : remaining;
            if (linelen > 6 && strncasecmp((const char*)p, "Host: ", 6) == 0) {
                unsigned int hl = linelen - 6;
                if (hl >= sizeof(host)) hl = sizeof(host) - 1;
                memcpy(host, p + 6, hl);
                host[hl] = '\0';
                char *cr = strchr(host, '\r');
                if (cr) *cr = '\0';
                break;
            }
            if (!nl) break;
            p = nl + 1;
            remaining -= (linelen + 1);
        }
        if (host[0]) {
            snprintf(pkt->info, sizeof(pkt->info), "%s (Host: %s)", line, host);
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "%s", line);
        }
    } else if (looks_like_http_response(data, len)) {
        snprintf(pkt->info, sizeof(pkt->info), "%s", line);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "HTTP segment/body (%u bytes)", len);
    }
}

static int extract_sni(const unsigned char *d, unsigned int len, char *out, size_t outlen) {
    if (len < 43) return -1;
    if (d[0] != 0x16) return -1; 
    if (d[5] != 0x01) return -1;

    size_t pos = 5 + 4;
    pos += 2;
    pos += 32;
    if (pos >= len) return -1;

    uint8_t session_id_len = d[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > len) return -1;

    uint16_t cipher_suites_len = (d[pos] << 8) | d[pos+1];
    pos += 2 + cipher_suites_len;
    if (pos + 1 > len) return -1;

    uint8_t comp_methods_len = d[pos];
    pos += 1 + comp_methods_len;
    if (pos + 2 > len) return -1;

    uint16_t ext_total_len = (d[pos] << 8) | d[pos+1];
    pos += 2;
    size_t ext_end = pos + ext_total_len;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (d[pos] << 8) | d[pos+1];
        uint16_t ext_len  = (d[pos+2] << 8) | d[pos+3];
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t p2 = pos + 2 + 1;
            if (p2 + 2 <= pos + ext_len) {
                uint16_t name_len = (d[p2] << 8) | d[p2+1];
                p2 += 2;
                if (p2 + name_len <= pos + ext_len && name_len < outlen) {
                    memcpy(out, d + p2, name_len);
                    out[name_len] = '\0';
                    return 0;
                }
            }
        }
        pos += ext_len;
    }
    return -1;
}

static void parse_https(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_HTTPS;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "HTTPS");

    char sni[128];
    if (len >= 6 && data[0] == 0x16 && extract_sni(data, len, sni, sizeof(sni)) == 0) {
        snprintf(pkt->info, sizeof(pkt->info), "TLS ClientHello, SNI: %s", sni);
    } else if (len >= 3 && data[0] == 0x16) {
        uint8_t msg_type = len > 5 ? data[5] : 0;
        const char *what = msg_type == 2 ? "ServerHello" :
                            msg_type == 11 ? "Certificate" :
                            msg_type == 16 ? "ClientKeyExchange" : "Handshake";
        snprintf(pkt->info, sizeof(pkt->info), "TLS %s", what);
    } else if (len >= 1 && data[0] == 0x17) {
        snprintf(pkt->info, sizeof(pkt->info), "TLS Application Data (%u bytes, encrypted)", len);
    } else if (len >= 1 && data[0] == 0x15) {
        snprintf(pkt->info, sizeof(pkt->info), "TLS Alert");
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "TLS/HTTPS segment (%u bytes)", len);
    }
}

static void parse_telnet(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_TELNET;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "TELNET");

    if (len == 0) {
        snprintf(pkt->info, sizeof(pkt->info), "empty segment");
        return;
    }
    if ((unsigned char)data[0] == 0xFF) {
        snprintf(pkt->info, sizeof(pkt->info), "Telnet option negotiation (IAC)");
        return;
    }
    char line[100];
    snprint_clean_line(line, sizeof(line), data, len);
    snprintf(pkt->info, sizeof(pkt->info), "Telnet data: \"%s\"", line);
    snprintf(pkt->alert_reason, sizeof(pkt->alert_reason), "cleartext protocol (telnet)");
    pkt->is_alert = 1;
}


static void parse_ftp(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_FTP;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "FTP");

    char line[128];
    snprint_clean_line(line, sizeof(line), data, len);
    snprintf(pkt->info, sizeof(pkt->info), "%s", line);

    if (len >= 5 && (strncasecmp((const char*)data, "USER ", 5) == 0 ||
                     strncasecmp((const char*)data, "PASS ", 5) == 0)) {
        snprintf(pkt->alert_reason, sizeof(pkt->alert_reason), "cleartext credentials (ftp)");
        pkt->is_alert = 1;
    }
}

static void parse_ftp_data(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    (void)data;
    pkt->proto = APP_PROTO_FTP_DATA;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "FTP-DATA");
    snprintf(pkt->info, sizeof(pkt->info), "FTP data transfer (%u bytes)", len);
}
static void parse_line_based_mail(const unsigned char *data, unsigned int len, NetPacket *pkt,
                                   AppProto proto, const char *proto_name,
                                   const char *cred_cmd_prefix) {
    pkt->proto = proto;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "%s", proto_name);

    char line[160];
    snprint_clean_line(line, sizeof(line), data, len);
    snprintf(pkt->info, sizeof(pkt->info), "%s", line);

    if (cred_cmd_prefix) {
        size_t plen = strlen(cred_cmd_prefix);
        if (len >= plen && strncasecmp((const char*)data, cred_cmd_prefix, plen) == 0) {
            snprintf(pkt->alert_reason, sizeof(pkt->alert_reason),
                     "possible cleartext credentials (%s)", proto_name);
            pkt->is_alert = 1;
        }
    }
}

static void parse_smtp(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    parse_line_based_mail(data, len, pkt, APP_PROTO_SMTP, "SMTP", "AUTH ");
}
static void parse_pop3(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    parse_line_based_mail(data, len, pkt, APP_PROTO_POP3, "POP3", "PASS ");
}
static void parse_imap(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    parse_line_based_mail(data, len, pkt, APP_PROTO_IMAP, "IMAP", "LOGIN ");
}

static void parse_generic_tls_wrapped(const unsigned char *data, unsigned int len,
                                      NetPacket *pkt, AppProto proto, const char *name) {
    pkt->proto = proto;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "%s", name);
    if (len >= 1 && data[0] == 0x16) {
        char sni[128];
        if (extract_sni(data, len, sni, sizeof(sni)) == 0)
            snprintf(pkt->info, sizeof(pkt->info), "TLS ClientHello, SNI: %s", sni);
        else
            snprintf(pkt->info, sizeof(pkt->info), "TLS handshake");
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "%s encrypted data (%u bytes)", name, len);
    }
}

static const char *ldap_op_name(uint8_t app_tag) {
    switch (app_tag & 0x1F) {
        case 0:  return "BindRequest";
        case 1:  return "BindResponse";
        case 2:  return "UnbindRequest";
        case 3:  return "SearchRequest";
        case 4:  return "SearchResultEntry";
        case 5:  return "SearchResultDone";
        case 6:  return "ModifyRequest";
        case 7:  return "ModifyResponse";
        case 8:  return "AddRequest";
        case 9:  return "AddResponse";
        case 10: return "DelRequest";
        case 11: return "DelResponse";
        case 12: return "ModifyDNRequest";
        case 13: return "ModifyDNResponse";
        case 14: return "CompareRequest";
        case 15: return "CompareResponse";
        case 16: return "AbandonRequest";
        case 19: return "SearchResultReference";
        case 24: return "ExtendedRequest";
        case 25: return "ExtendedResponse";
        default: return "Op?";
    }
}

static int ber_read_len(const unsigned char *d, unsigned int len, unsigned int *pos, uint32_t *out_len) {
    if (*pos >= len) return -1;
    uint8_t first = d[*pos];
    (*pos)++;
    if (!(first & 0x80)) {
        *out_len = first;
        return 0;
    }
    uint8_t nbytes = first & 0x7F;
    if (nbytes == 0 || nbytes > 4 || *pos + nbytes > len) return -1;
    uint32_t v = 0;
    for (uint8_t i = 0; i < nbytes; i++) v = (v << 8) | d[*pos + i];
    *pos += nbytes;
    *out_len = v;
    return 0;
}

static void parse_ldap(const unsigned char *data, unsigned int len, NetPacket *pkt, int is_tls) {
    pkt->proto = is_tls ? APP_PROTO_LDAPS : APP_PROTO_LDAP;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "%s", is_tls ? "LDAPS" : "LDAP");

    if (is_tls) {
        parse_generic_tls_wrapped(data, len, pkt, APP_PROTO_LDAPS, "LDAPS");
        return;
    }

    if (len < 6 || data[0] != 0x30) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP segment (%u bytes)", len);
        return;
    }
    unsigned int pos = 1;
    uint32_t seq_len;
    if (ber_read_len(data, len, &pos, &seq_len) < 0) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP malformed BER");
        return;
    }
    if (pos >= len || data[pos] != 0x02) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP message (unexpected messageID tag)");
        return;
    }
    pos++;
    uint32_t msgid_len;
    if (ber_read_len(data, len, &pos, &msgid_len) < 0 || pos + msgid_len > len) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP malformed messageID");
        return;
    }
    uint32_t message_id = 0;
    for (uint32_t i = 0; i < msgid_len && i < 4; i++) message_id = (message_id << 8) | data[pos + i];
    pos += msgid_len;

    if (pos >= len) {
        snprintf(pkt->info, sizeof(pkt->info), "LDAP message id=%u (truncated)", message_id);
        return;
    }
    uint8_t op_tag = data[pos];
    const char *opname = ldap_op_name(op_tag);

    snprintf(pkt->info, sizeof(pkt->info), "LDAP %s (msgid=%u)", opname, message_id);

    if ((op_tag & 0x1F) == 0) {
        snprintf(pkt->alert_reason, sizeof(pkt->alert_reason), "LDAP simple bind (check for cleartext creds)");
        pkt->is_alert = 1;
    }
}
static const char *mysql_command_name(uint8_t cmd) {
    switch (cmd) {
        case 0x00: return "COM_SLEEP";
        case 0x01: return "COM_QUIT";
        case 0x02: return "COM_INIT_DB";
        case 0x03: return "COM_QUERY";
        case 0x04: return "COM_FIELD_LIST";
        case 0x05: return "COM_CREATE_DB";
        case 0x06: return "COM_DROP_DB";
        case 0x0e: return "COM_PING";
        case 0x16: return "COM_STMT_PREPARE";
        case 0x17: return "COM_STMT_EXECUTE";
        default:   return NULL;
    }
}

static void parse_mysql(const unsigned char *data, unsigned int len, NetPacket *pkt,
                         uint16_t src_port) {
    pkt->proto = APP_PROTO_MYSQL;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "MYSQL");

    if (len < 5) {
        snprintf(pkt->info, sizeof(pkt->info), "MySQL segment (%u bytes)", len);
        return;
    }
    uint32_t payload_len = data[0] | (data[1] << 8) | (data[2] << 16);
    uint8_t seq_id = data[3];
    const unsigned char *payload = data + 4;
    unsigned int payload_avail = len - 4;
    if (payload_avail == 0) {
        snprintf(pkt->info, sizeof(pkt->info), "MySQL packet header only (len=%u, seq=%u)",
                 payload_len, seq_id);
        return;
    }

    if (src_port == 3306 && seq_id == 0 && payload[0] >= 9 && payload[0] <= 12) {
        snprintf(pkt->info, sizeof(pkt->info), "MySQL server handshake (protocol v%u)", payload[0]);
        return;
    }

    const char *cmdname = mysql_command_name(payload[0]);
    if (cmdname) {
        if (payload[0] == 0x03 && payload_avail > 1) {
            char q[120];
            snprint_clean_line(q, sizeof(q), payload + 1, payload_avail - 1);
            snprintf(pkt->info, sizeof(pkt->info), "MySQL %s: %s", cmdname, q);
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "MySQL %s", cmdname);
        }
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "MySQL packet (seq=%u, %u bytes payload)",
                 seq_id, payload_avail);
    }
}
static void parse_postgres(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_POSTGRESQL;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "POSTGRESQL");

    if (len < 5) {
        snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL segment (%u bytes)", len);
        return;
    }

    uint32_t maybe_len = ntohl(*(const uint32_t*)data);
    if (len >= 8) {
        uint32_t proto_ver = ntohl(*(const uint32_t*)(data + 4));
        if (maybe_len == len && (proto_ver == 0x00030000)) {
            const char *params = (const char*)data + 8;
            unsigned int params_len = len > 8 ? len - 8 : 0;
            const char *user_kv = NULL;
            for (unsigned int i = 0; i + 5 <= params_len; i++) {
                if (memcmp(params + i, "user", 4) == 0 && params[i+4] == '\0') {
                    user_kv = params + i + 5;
                    break;
                }
            }
            if (user_kv) {
                char uname[64];
                snprint_clean_line(uname, sizeof(uname), (const unsigned char*)user_kv,
                                    params_len - (unsigned int)(user_kv - params));
                snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL StartupMessage (user=%s)", uname);
            } else {
                snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL StartupMessage");
            }
            return;
        }
    }

    char type = (char)data[0];
    const char *desc = NULL;
    int is_credential_msg = 0;
    switch (type) {
        case 'Q': desc = "Simple Query"; break;
        case 'P': desc = "Parse (prepared statement)"; break;
        case 'p': desc = "PasswordMessage"; is_credential_msg = 1; break;
        case 'R': desc = "Authentication"; break;
        case 'E': desc = "ErrorResponse"; break;
        case 'Z': desc = "ReadyForQuery"; break;
        case 'C': desc = "CommandComplete"; break;
        case 'T': desc = "RowDescription"; break;
        case 'D': desc = "DataRow"; break;
        default:  desc = NULL; break;
    }

    if (desc) {
        if (type == 'Q' && len > 5) {
            char q[100];
            snprint_clean_line(q, sizeof(q), data + 5, len - 5);
            snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL %s: %s", desc, q);
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL %s", desc);
        }
        if (is_credential_msg) {
            snprintf(pkt->alert_reason, sizeof(pkt->alert_reason), "PostgreSQL password message observed");
            pkt->is_alert = 1;
        }
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "PostgreSQL message type '%c' (%u bytes)", type, len);
    }
}
#define MONGO_OP_MSG    2013
#define MONGO_OP_QUERY  2004
#define MONGO_OP_REPLY  1

static const char *mongo_opcode_name(int32_t opcode) {
    switch (opcode) {
        case MONGO_OP_MSG:   return "OP_MSG";
        case MONGO_OP_QUERY: return "OP_QUERY";
        case MONGO_OP_REPLY: return "OP_REPLY";
        case 2010: return "OP_COMMAND";
        case 2011: return "OP_COMMANDREPLY";
        case 2002: return "OP_INSERT";
        case 2006: return "OP_DELETE";
        case 2001: return "OP_UPDATE";
        default: return NULL;
    }
}

static int bson_first_key(const unsigned char *d, unsigned int len, char *out, size_t outlen) {
    if (len < 5) return -1;
    unsigned int pos = 4;
    if (pos >= len) return -1;
    uint8_t elem_type = d[pos];
    if (elem_type == 0x00) return -1;
    pos++;
    unsigned int start = pos;
    while (pos < len && d[pos] != 0x00) pos++;
    if (pos >= len) return -1;
    unsigned int keylen = pos - start;
    if (keylen == 0 || keylen >= outlen) return -1;
    memcpy(out, d + start, keylen);
    out[keylen] = '\0';
    return 0;
}

static void parse_mongodb(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_MONGODB;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "MONGODB");

    if (len < 16) {
        snprintf(pkt->info, sizeof(pkt->info), "MongoDB segment (%u bytes)", len);
        return;
    }
    int32_t msg_len   = (int32_t)(data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24));
    int32_t opcode    = (int32_t)(data[12] | (data[13]<<8) | (data[14]<<16) | (data[15]<<24));
    const char *opname = mongo_opcode_name(opcode);

    if (!opname) {
        snprintf(pkt->info, sizeof(pkt->info), "MongoDB opcode=%d (%d bytes msg)", opcode, msg_len);
        return;
    }

    if (opcode == MONGO_OP_MSG && len > 16) {
        if (16 + 4 < len) {
            uint8_t kind = data[16 + 4];
            unsigned int bson_start = 16 + 4 + 1;
            if (kind == 0 && bson_start < len) {
                char key[32];
                if (bson_first_key(data + bson_start, len - bson_start, key, sizeof(key)) == 0) {
                    snprintf(pkt->info, sizeof(pkt->info), "MongoDB %s: command=%s", opname, key);
                    return;
                }
            }
        }
        snprintf(pkt->info, sizeof(pkt->info), "MongoDB %s", opname);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "MongoDB %s (%d bytes)", opname, msg_len);
    }
}
static const char *smb2_command_name(uint16_t cmd) {
    switch (cmd) {
        case 0x0000: return "Negotiate";
        case 0x0001: return "SessionSetup";
        case 0x0002: return "Logoff";
        case 0x0003: return "TreeConnect";
        case 0x0004: return "TreeDisconnect";
        case 0x0005: return "Create";
        case 0x0006: return "Close";
        case 0x0008: return "Read";
        case 0x0009: return "Write";
        case 0x000e: return "Ioctl";
        case 0x0011: return "Find";
        case 0x0012: return "Notify";
        default: return NULL;
    }
}

static void parse_smb(const unsigned char *data, unsigned int len, NetPacket *pkt) {
    pkt->proto = APP_PROTO_SMB;
    snprintf(pkt->proto_str, sizeof(pkt->proto_str), "SMB");

    unsigned int off = 0;
    if (len >= 4 && data[0] == 0x00 && len > 4) {
        off = 4;
    }
    if (len < off + 4) {
        snprintf(pkt->info, sizeof(pkt->info), "SMB segment (%u bytes)", len);
        return;
    }
    const unsigned char *hdr = data + off;
    unsigned int hdr_len = len - off;

    if (hdr_len >= 4 && hdr[0] == 0xFE && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B') {
        if (hdr_len >= 14) {
            uint16_t command = hdr[12] | (hdr[13] << 8);
            const char *cname = smb2_command_name(command);
            snprintf(pkt->info, sizeof(pkt->info), "SMB2 %s", cname ? cname : "command");
        } else {
            snprintf(pkt->info, sizeof(pkt->info), "SMB2 header (truncated)");
        }
    } else if (hdr_len >= 4 && hdr[0] == 0xFF && hdr[1] == 'S' && hdr[2] == 'M' && hdr[3] == 'B') {
        uint8_t smb_cmd = hdr_len > 4 ? hdr[4] : 0;
        snprintf(pkt->info, sizeof(pkt->info), "SMB1 command=0x%02x", smb_cmd);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "SMB/NetBIOS session data (%u bytes)", len);
    }
}
void net_proto_parse_tcp(const unsigned char *payload, unsigned int payload_len, NetPacket *pkt) {
    pkt->proto_str[0] = '\0';
    pkt->info[0] = '\0';

    if (payload_len < sizeof(TcpHeader)) {
        snprintf(pkt->proto_str, sizeof(pkt->proto_str), "TCP");
        snprintf(pkt->info, sizeof(pkt->info), "truncated TCP segment");
        return;
    }

    const TcpHeader *tcp = (const TcpHeader *)payload;
    uint8_t data_offset_words = (tcp->data_off_reserved >> 4) & 0x0F;
    uint32_t hdr_bytes = data_offset_words * 4u;
    if (hdr_bytes < sizeof(TcpHeader)) hdr_bytes = sizeof(TcpHeader);

    pkt->src_port = ntohs(tcp->src_port);
    pkt->dst_port = ntohs(tcp->dst_port);

    const unsigned char *app_data = payload + hdr_bytes;
    unsigned int app_len = (hdr_bytes < payload_len) ? (payload_len - hdr_bytes) : 0;

    char flagstr[16] = "";
    int fo = 0;
    if (tcp->flags & TCP_FLAG_SYN) flagstr[fo++] = 'S';
    if (tcp->flags & TCP_FLAG_ACK) flagstr[fo++] = 'A';
    if (tcp->flags & TCP_FLAG_FIN) flagstr[fo++] = 'F';
    if (tcp->flags & TCP_FLAG_RST) flagstr[fo++] = 'R';
    if (tcp->flags & TCP_FLAG_PSH) flagstr[fo++] = 'P';
    if (tcp->flags & TCP_FLAG_URG) flagstr[fo++] = 'U';
    flagstr[fo] = '\0';

    if (app_len == 0) {
        pkt->proto = APP_PROTO_TCP;
        snprintf(pkt->proto_str, sizeof(pkt->proto_str), "TCP");
        snprintf(pkt->info, sizeof(pkt->info), "%u -> %u [%s] seq=%u ack=%u win=%u",
                 pkt->src_port, pkt->dst_port, flagstr, tcp->seq, tcp->ack, ntohs(tcp->window));

        if ((tcp->flags & TCP_FLAG_SYN) && !(tcp->flags & TCP_FLAG_ACK)) {
            snprintf(pkt->alert_reason, sizeof(pkt->alert_reason), "SYN probe to port %u", pkt->dst_port);
        }
        return;
    }

    AppProto proto = proto_by_port(pkt->dst_port);
    if (proto == APP_PROTO_UNKNOWN) proto = proto_by_port(pkt->src_port);

    if (proto == APP_PROTO_UNKNOWN) {
        if (looks_like_http_request(app_data, app_len) || looks_like_http_response(app_data, app_len))
            proto = APP_PROTO_HTTP;
        else if (app_len >= 1 && (app_data[0] == 0x16 || app_data[0] == 0x17 || app_data[0] == 0x15))
            proto = APP_PROTO_HTTPS;
    }

    switch (proto) {
        case APP_PROTO_HTTP:       parse_http(app_data, app_len, pkt); break;
        case APP_PROTO_HTTPS:      parse_https(app_data, app_len, pkt); break;
        case APP_PROTO_SMTP:       parse_smtp(app_data, app_len, pkt); break;
        case APP_PROTO_SMTPS:      parse_generic_tls_wrapped(app_data, app_len, pkt, APP_PROTO_SMTPS, "SMTPS"); break;
        case APP_PROTO_TELNET:     parse_telnet(app_data, app_len, pkt); break;
        case APP_PROTO_FTP:        parse_ftp(app_data, app_len, pkt); break;
        case APP_PROTO_FTP_DATA:   parse_ftp_data(app_data, app_len, pkt); break;
        case APP_PROTO_POP3:       parse_pop3(app_data, app_len, pkt); break;
        case APP_PROTO_POP3S:      parse_generic_tls_wrapped(app_data, app_len, pkt, APP_PROTO_POP3S, "POP3S"); break;
        case APP_PROTO_IMAP:       parse_imap(app_data, app_len, pkt); break;
        case APP_PROTO_IMAPS:      parse_generic_tls_wrapped(app_data, app_len, pkt, APP_PROTO_IMAPS, "IMAPS"); break;
        case APP_PROTO_LDAP:       parse_ldap(app_data, app_len, pkt, 0); break;
        case APP_PROTO_LDAPS:      parse_ldap(app_data, app_len, pkt, 1); break;
        case APP_PROTO_MYSQL:      parse_mysql(app_data, app_len, pkt, pkt->src_port); break;
        case APP_PROTO_POSTGRESQL: parse_postgres(app_data, app_len, pkt); break;
        case APP_PROTO_MONGODB:    parse_mongodb(app_data, app_len, pkt); break;
        case APP_PROTO_SMB:        parse_smb(app_data, app_len, pkt); break;
        default:
            pkt->proto = APP_PROTO_TCP;
            snprintf(pkt->proto_str, sizeof(pkt->proto_str), "TCP");
            snprintf(pkt->info, sizeof(pkt->info), "%u -> %u [%s] payload %u bytes",
                     pkt->src_port, pkt->dst_port, flagstr, app_len);
            break;
    }
}