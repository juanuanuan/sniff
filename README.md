# Packet Sniffer

A packet sniffer written in C using libpcap. It captures traffic on a network interface and decodes Ethernet, IPv4 and TCP/UDP/ICMP headers.

A learning project in cybersecurity and networking. Tested on macOS.

## Features

- Lists the available network interfaces
- Captures packets on a chosen Ethernet interface
- Decodes Ethernet, IPv4 and TCP/UDP/ICMP headers
- Prints, for each packet: MAC addresses, source and destination IPs, ports, TCP flags and ICMP type
- Optional BPF filter (same syntax as `tcpdump`)
- Bounds checking on every header, so truncated or malformed packets are reported instead of read out of bounds

## Requirements

- A C compiler (`gcc` or `clang`)
- libpcap (included with macOS)
- `sudo`, since capturing packets needs elevated privileges

## Build and run

```bash
cd src
make
sudo ./bin/sniffer <interface> ["<bpf filter>"]
```

Examples:

```bash
sudo ./bin/sniffer en0
sudo ./bin/sniffer en0 "udp port 443"
sudo ./bin/sniffer en0 "tcp port 80"
sudo ./bin/sniffer en0 "icmp"
```

### Make shortcuts

```bash
make run                                       # capture on en0, no filter
make run IFACE=en1                             # choose the interface
make filter FILTER="udp port 443"              # capture with a BPF filter
make filter IFACE=en1 FILTER="tcp port 80"
make clean                                     # remove the binary
```

## Example output

(MAC addresses anonymized.)

```
--------------------
Header Length: 1292
Header Caplen: 1292
Ether info:
dhost: aa:bb:cc:dd:ee:ff
shost: 11:22:33:44:55:66
IPv4: 0800
src ipaddr: 172.26.218.137
dst ipaddr: 160.79.104.10
UDP Src Port: 52799
UDP Dst Port: 443
```

## Limitations (For now)

- IPv4 only (no IPv6)
- Ethernet interfaces only (e.g. `en0`); the loopback interface (`lo0`) is not supported
- No TCP stream reconstruction or payload analysis
- Only tested on macOS

## What I learned

- Structure of Ethernet, IP and TCP/UDP headers, and how the IP header length (IHL) determines offsets
- Network byte order (`ntohs`/`ntohl`)
- Working with libpcap: device discovery, capture loop, BPF filters
- Validating packet lengths before reading headers