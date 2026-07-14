CC?=gcc
CFLAGS?= -Wall -Wextra -O2 -Inetwork
LDFLAGS?=

PKG_CFLAGS:=$(shell pkg-config --cflags gtk+-3.0)
PKG_LIBS:=$(shell pkg-config --libs gtk+-3.0)

SRCS:=main.c network/net_capture.c network/net_proto.c network/net_proto_tcp.c network/net_proto_udp.c db.c log.c

OBJS:=$(SRCS:.c=.o)
TARGET:=siem

.PHONY: all run clean caps

all: $(TARGET)

$(TARGET): $(OBJS)
	@$(CC) $(OBJS) $(PKG_CFLAGS) $(PKG_LIBS) -lpcap -lsqlite3 $(LDFLAGS) -o $@

%.o: %.c
	@$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

caps: $(TARGET)
	sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET)

run: caps
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)