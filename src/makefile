CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

IFACE ?= en0

TARGET = bin/sniffer
SRC = sniffer.c

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

run: $(TARGET)
	sudo ./$(TARGET) $(IFACE)

filter: $(TARGET)
	sudo ./$(TARGET) $(IFACE) "$(FILTER)"

clean:
	rm -f $(TARGET)

.PHONY: all run filter clean