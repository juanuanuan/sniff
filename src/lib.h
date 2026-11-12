#ifdef LIB_H
#define LIB_H


int finder();
void handtcp(const u_char *segment, bpf_u_int32 len);
void handudp(const u_char *segment, bpf_u_int32 len);
void handicmp(const u_char *segment, bpf_u_int32 len);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);
int grabber(const char *dev);

#endif