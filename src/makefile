CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

TARGET = bin/sniffer
SRC = sniffer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

run: $(TARGET)
	sudo ./$(TARGET) en0

clean:
	rm -f $(TARGET)

.PHONY: all run clean