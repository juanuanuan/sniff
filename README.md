# Packet Sniffer
 
A Linux packet sniffer written in C that captures traffic using raw sockets (`AF_PACKET`) and decodes Ethernet, IPv4 and TCP/UDP/ICMP headers.
 
A learning project in cybersecurity and networking.
 
## Features
 
- Captures packets on a network interface
- Decodes Ethernet, IPv4 and TCP/UDP/ICMP headers
- Prints one line per packet: protocol, source and destination IPs, ports and TCP flags
 
## Limitations
 
- Linux only
- IPv4 only (no IPv6)
- No TCP stream reconstruction or payload analysis
