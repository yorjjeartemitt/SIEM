CC = gcc
CFLAGS = -Wall -g `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0`
SRC = main.c log.c db.c
BIN = siem

$(BIN): $(SRC) log.h
	$(CC) $(SRC) -o $(BIN) $(CFLAGS) $(LIBS)

run: $(BIN)
	GDK_BACKEND=wayland ./$(BIN)

clean:
	rm -f $(BIN)
	rm -f siem.db

.PHONY: run clean