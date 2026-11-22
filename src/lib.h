#ifndef LIB_H
#define LIB_H

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <time.h>

#define BUFSIZZ 65535
#define ICMP_HDR_LEN 8 //ICMP is usually smaller (at least on macOS), so 8 bytes is probably enough
#define MAX_PORTS 32
#define MAX_ENTRIES 64
#define WINDOW_SECS 5
#define THRESHOLD 15
pcap_t *loop;

typedef struct{
    time_t start;
    int nports;
    u_short ports[MAX_PORTS];
    struct in_addr addr;
} ptable; //port table

ptable syntable[MAX_ENTRIES]; // we could use a hashtable to handle a huge amount of ip adresses, but for now, an array is sufficient
int nentries;  


int finder();
void detectsyn(struct in_addr src, u_short dport, time_t now);
void handtcp(const struct in_addr, u_char *segment, bpf_u_int32 len, time_t now);
void handudp(const u_char *segment, bpf_u_int32 len);
void handicmp(const u_char *segment, bpf_u_int32 len);
void gotpacket(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);
int grabber(const char *dev, const char *expr);

#endif