FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libgtk-3-dev \
    libsqlite3-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN gcc main.c network/net_capture.c network/net_proto.c network/net_proto_tcp.c network/net_proto_udp.c db.c log.c \
    -Inetwork \
    $(pkg-config --cflags --libs gtk+-3.0) -lpcap -lsqlite3 -o siem
FROM ubuntu:22.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgtk-3-0 \
    libsqlite3-0 \
    libpcap0.8 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/siem /app/siem

RUN setcap cap_net_raw,cap_net_admin=eip /app/siem

ENV GDK_BACKEND=wayland

ENTRYPOINT ["/app/siem"]