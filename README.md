# Packet Sniffer
 
A Linux packet sniffer written in C that captures traffic using raw sockets (`AF_PACKET`) and decodes Ethernet, IPv4 and TCP/UDP/ICMP headers.
 
A learning project in cybersecurity and networking.
 
## Features
 
- Captures packets on a network interface
- Decodes Ethernet, IPv4 and TCP/UDP/ICMP headers
- Prints one line per packet: protocol, source and destination IPs, ports and TCP flags
## Build and run
 
```bash
gcc -Wall -Wextra -o sniffer sniffer.c
sudo ./sniffer [interface]
```
 
Requires root (or `CAP_NET_RAW`).
 
## Example output
 
```
TCP  192.168.1.10:51234 -> 93.184.216.34:443  [SYN]
UDP  192.168.1.10:53211 -> 1.1.1.1:53
ICMP 192.168.1.10 -> 192.168.1.1
```
 
## Limitations
 
- Linux only
- IPv4 only (no IPv6)
- No TCP stream reconstruction or payload analysis
