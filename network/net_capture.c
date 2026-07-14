#include "net_capture.h"
#include "net_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct NetCapture {
    pcap_t *handle;
    int is_offline;
    int datalink;
};

int net_list_interfaces(NetIfaceInfo *out, int max_count, char *errbuf) {
    pcap_if_t *alldevs, *d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return -1;

    int n = 0;
    for (d = alldevs; d != NULL && n < max_count; d = d->next) {
        snprintf(out[n].name, sizeof(out[n].name), "%s", d->name ? d->name : "");
        snprintf(out[n].description, sizeof(out[n].description), "%s",
                  d->description ? d->description : "");
        n++;
    }
    pcap_freealldevs(alldevs);
    return n;
}
static NetCapture *finish_open(pcap_t *handle, const char *bpf_filter, char *errbuf) {
    if (!handle) return NULL;

    if (bpf_filter && bpf_filter[0]) {
        struct bpf_program prog;
        if (pcap_compile(handle, &prog, bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "bpf compile: %s", pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
        if (pcap_setfilter(handle, &prog) == -1) {
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "bpf setfilter: %s", pcap_geterr(handle));
            pcap_freecode(&prog);
            pcap_close(handle);
            return NULL;
        }
        pcap_freecode(&prog);
    }

    NetCapture *cap = calloc(1, sizeof(NetCapture));
    cap->handle = handle;
    cap->datalink = pcap_datalink(handle);
    return cap;
}

NetCapture *net_capture_open_live(const char *iface, int promisc, int snaplen,
                                   const char *bpf_filter, char *errbuf) {
    char default_iface_buf[64];
    if (!iface) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            if (!errbuf[0]) snprintf(errbuf, PCAP_ERRBUF_SIZE, "no interfaces found");
            return NULL;
        }
        snprintf(default_iface_buf, sizeof(default_iface_buf), "%s", alldevs->name);
        pcap_freealldevs(alldevs);
        iface = default_iface_buf;
    }
    if (snaplen <= 0) snaplen = 65535;

    pcap_t *handle = pcap_create(iface, errbuf);
    if (!handle) return NULL;

    pcap_set_snaplen(handle, snaplen);
    pcap_set_promisc(handle, promisc ? 1 : 0);
    pcap_set_timeout(handle, 100);
    pcap_set_immediate_mode(handle, 1);

    int rc = pcap_activate(handle);
    if (rc < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_activate: %s", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        pcap_close(handle);
        return NULL;
    }
    return finish_open(handle, bpf_filter, errbuf);
}

NetCapture *net_capture_open_offline(const char *filepath, char *errbuf) {
    pcap_t *handle = pcap_open_offline(filepath, errbuf);
    if (!handle) return NULL;
    NetCapture *cap = finish_open(handle, NULL, errbuf);
    if (cap) cap->is_offline = 1;
    return cap;
}

int net_capture_get_fd(NetCapture *cap) {
    if (!cap || cap->is_offline) return -1;
    return pcap_get_selectable_fd(cap->handle);
}

void net_capture_close(NetCapture *cap) {
    if (!cap) return;
    if (cap->handle) pcap_close(cap->handle);
    free(cap);
}

int net_capture_get_stats(NetCapture *cap, NetCaptureStats *out) {
    if (!cap || cap->is_offline) return -1;
    struct pcap_stat ps;
    if (pcap_stats(cap->handle, &ps) < 0) return -1;
    out->recv = ps.ps_recv;
    out->dropped_kernel = ps.ps_drop;
    out->dropped_iface = ps.ps_ifdrop;
    return 0;
}


static void format_ts(const struct timeval *tv, char *out, size_t outlen) {
    struct tm tmv;
    time_t sec = tv->tv_sec;
    localtime_r(&sec, &tmv);
    char base[16];
    strftime(base, sizeof(base), "%H:%M:%S", &tmv);
    long ms=(long)(tv->tv_usec/1000)%1000;
    snprintf(out, outlen, "%s.%03ld", base, ms);
}
typedef struct {
    NetPacketCallback user_cb;
    void *user_data;
    int datalink;
} DispatchCtx;
static void on_raw_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    DispatchCtx *ctx = (DispatchCtx *)user;
    NetPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.length = h->len;
    format_ts(&h->ts, pkt.timestamp, sizeof(pkt.timestamp));
    if (net_proto_parse(bytes, h->caplen, ctx->datalink, &pkt) != 0) {
        snprintf(pkt.proto_str, sizeof(pkt.proto_str), "RAW");
        snprintf(pkt.info, sizeof(pkt.info), "unparsed link-layer frame (%u bytes)", h->caplen);
    }
    ctx->user_cb(&pkt, ctx->user_data);
}
int net_capture_poll(NetCapture *cap, int max_packets,NetPacketCallback cb, void *user_data) {
    if (!cap || !cb) return -1;
    DispatchCtx ctx = { .user_cb = cb, .user_data = user_data, .datalink = cap->datalink };
    int rc = pcap_dispatch(cap->handle, max_packets, on_raw_packet, (u_char *)&ctx);
    if (rc == 0 && cap->is_offline) {
        struct pcap_pkthdr *hdr;
        const u_char *data;
        int r2 = pcap_next_ex(cap->handle, &hdr, &data);
        if (r2 == -2 || r2 == -1) return -1;
        if (r2 == 1) {
            on_raw_packet((u_char *)&ctx, hdr, data);
            return 1;
        }
    }
    return rc;
}