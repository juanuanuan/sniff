# Packet Sniffer

A Linux packet sniffer written in C that captures traffic using `libcap` and decodes Ethernet, IPv4 and TCP/UDP/ICMP headers.

A learning project in cybersecurity and networking.

## Features

- Captures packets on a network interface
- Decodes Ethernet, IPv4 and TCP/UDP/ICMP headers
- Prints one line per packet: protocol, source and destination IPs, ports and TCP flags

## Build and run

```bash
make clean
make 
make run
```


## Example output

```
TCP  192.168.1.10:51234 -> 93.184.216.34:443  [SYN]
UDP  192.168.1.10:53211 -> 1.1.1.1:53
ICMP 192.168.1.10 -> 192.168.1.1
```

## Limitations (For now)

- IPv4 only (no IPv6)
- No TCP stream reconstruction or payload analysis


## What I learned

- Structure of Ethernet, IP and TCP headers, and how the IHL field determines offsets
- Network byte order (`ntohs`/`ntohl`)
- Working with libcap