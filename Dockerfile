FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    libgtk-3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN gcc main.c log.c -o siem \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -Wall

ENV GDK_BACKEND=wayland

CMD ["./siem"]