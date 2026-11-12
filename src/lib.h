#ifdef LIB_H
#define LIB_H


int finder();
void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);
int grabber(const char *dev);

#endif