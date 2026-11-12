#include "lib.h"
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
#include <arpa/inet.h>
#define BUFSIZZ 65535

int finder(){
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if(pcap_findalldevs(&alldevs, errbuff) == -1){
        fprintf(stderr, "Could not find device: %s\n", errbuff);
        return -1;
    }

    pcap_if_t *d = alldevs;
    
    for(;d != NULL; d = d->next){
        fprintf(stdout, "Device: %s\n", d->name);
        fflush(stdout);
    }

    pcap_freealldevs(alldevs);
    return 0;
}

void handtcp(const u_char *segment, bpf_u_int32 len){
    if(len < sizeof(struct tcphdr)){
        fprintf(stderr, "TCP Length Error\n");
        return;
    }

    const struct tcphdr *t = (const struct tcphdr *) segment; 
    fprintf(stdout, "TCP Src Port: %u\n", ntohs(t->th_sport));
    fprintf(stdout, "TCP Dst Port: %u\n", ntohs(t->th_dport));

    //if((t->th_flags & TH_SYN) && !(t->th_flags & TH_ACK)) fprintf(stdout, "SYNNOACK: %u\n", t->th_flags);

    if(t->th_flags & TH_SYN) fprintf(stdout, "SYN: %u\n", t->th_flags);

    if(t->th_flags & TH_FIN) fprintf(stdout, "FIN: %u\n", t->th_flags);

    if(t->th_flags & TH_ACK) fprintf(stdout, "ACK: %u\n", t->th_flags);

    if(t->th_flags & TH_RST) fprintf(stdout, "RST: %u\n", t->th_flags);

    if(t->th_flags & TH_PUSH) fprintf(stdout, "PUSH: %u\n", t->th_flags);

    fflush(stdout);
}

void handudp(const u_char *segment, bpf_u_int32 len){
    if(len < sizeof(struct udphdr)){
        fprintf(stderr, "UDP Length Error\n");
        return;
    }

    const struct udphdr *ud = (const struct udphdr *) segment; 
    fprintf(stdout, "UDP Src Port: %u\n", ntohs(ud->uh_sport));
    fprintf(stdout, "UDP Dst Port: %u\n", ntohs(ud->uh_dport));
    fflush(stdout);
}

void handicmp(const u_char *segment, bpf_u_int32 len){
    if(len < sizeof(struct icmp)){
        fprintf(stderr, "UDP Length Error\n");
        return;
    }

    const struct icmp *ic = (const struct icmp *) segment; 
    fprintf(stdout, "ICMP Type: %u\n", ntohs(ic->icmp_type));
    fflush(stdout);
}


void gotpacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    (void)args;
    const struct ether_header *eth = (const struct ether_header *) packet;
    fprintf(stdout, "\n--------------------\n");
    fprintf(stdout, "Header Length: %u\n", header->len);
    fprintf(stdout, "Header Caplen: %u\n", header->caplen);
    fprintf(stdout, "Ether info:\n");
    fprintf(stdout, "dhost: %s\n", ether_ntoa((const struct ether_addr *) eth->ether_dhost)); // macs
    fprintf(stdout, "shost: %s\n", ether_ntoa((const struct ether_addr *) eth->ether_shost));
    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
        fprintf(stdout, "IPv4: %04x\n", ntohs(eth->ether_type));
        if(header->caplen >= sizeof(struct ether_header) + sizeof(struct ip)){
            const struct ip *ipaddr = (const struct ip *)(packet + sizeof(struct ether_header)); // we have to look 14 bytes ahead to serch for the ip addr
            char src_buf[INET_ADDRSTRLEN];
            char dst_buf[INET_ADDRSTRLEN];
            const char *src = inet_ntop(AF_INET, &ipaddr->ip_src, src_buf, sizeof(src_buf));
            const char *dst = inet_ntop(AF_INET, &ipaddr->ip_dst, dst_buf, sizeof(dst_buf));
            if(src == NULL){
                fprintf(stderr, "SRC might not be defined.\n");
                return;
            }
            if(dst == NULL){
                fprintf(stderr, "DST might not be defined.\n");
                return;
            }
            fprintf(stdout, "src ipaddr: %s\n", src);
            fprintf(stdout, "dst ipaddr: %s\n", dst);
            if(ipaddr->ip_p == IPPROTO_TCP){
                u_int offset = sizeof(struct ether_header) + ipaddr->ip_hl * 4;
                if((ipaddr->ip_hl >= 5) && header->caplen >= offset){
                    handtcp(packet + offset, header->caplen - offset);
                } else if(!(ipaddr->ip_hl >= 5)){
                    fprintf(stderr, "Length might not be enough\n");
                    return;
                } else if(!(header->caplen >= offset)){
                    fprintf(stderr, "Caplen might not be enough\n");
                    return;
                }
            } else if(ipaddr->ip_p == IPPROTO_UDP){
                u_int offset = sizeof(struct ether_header) + ipaddr->ip_hl * 4;
                if((ipaddr->ip_hl >= 5) && header->caplen >= offset){
                    handudp(packet + offset, header->caplen - offset);
                } else if(!(ipaddr->ip_hl >= 5)){
                    fprintf(stderr, "Length might not be enough\n");
                    return;
                } else if(!(header->caplen >= offset)){
                    fprintf(stderr, "Caplen might not be enough\n");
                    return;
                }
            } else if(ipaddr->ip_p == IPPROTO_ICMP){
                u_int offset = sizeof(struct ether_header) + ipaddr->ip_hl * 4;
                if((ipaddr->ip_hl >= 5) && header->caplen >= offset){
                    handicmp(packet + offset, header->caplen - offset);
                } else if(!(ipaddr->ip_hl >= 5)){
                    fprintf(stderr, "Length might not be enough\n");
                    return;
                } else if(!(header->caplen >= offset)){
                    fprintf(stderr, "Caplen might not be enough\n");
                    return;
                }
            } else {
                fprintf(stdout, "Other: %u\n", ipaddr->ip_p);
            }
        } else {
            fprintf(stderr, "Caplen is too small.");
            return;
        }
    } else fprintf(stdout, "Not Ipv4.\n"); fflush(stdout);
}

int grabber(const char *dev, const char *expr){
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZZ, 1, 1000, errbuff);
    struct bpf_program fp; //for filtering 
    if(handle == NULL){
        fprintf(stderr, "Could not open Device: %s\n", errbuff);
        return -1;
    }
    if(expr != NULL){
        if(pcap_compile(handle, &fp, expr, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "Compilation Error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
        }
        if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Filter Error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freecode(&fp);
        return -1;
        }

        pcap_freecode(&fp);
    }

     if(pcap_datalink(handle) != DLT_EN10MB){ // checks if ethernet
        fprintf(stderr, "Not linked: Current interface is not Ethernet\n");
        pcap_close(handle);
        return -1;
    }
    if(pcap_loop(handle, 10, gotpacket, NULL) == -1){
        fprintf(stderr, "Could not loop: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);
    return 0;
}



int main(int argc, char **argv){
    if(argc < 2){
        fprintf(stderr, "Usage: %s <Interface>\n", argv[0]);
        return -1;
    }
    if(finder() == -1){
        fprintf(stderr, "Could not find any device\n");
        return -1;
    }

    if(grabber(argv[1], argv[2]) == -1){
        fprintf(stderr, "Could not grab any device\n");
        return -1;
    }

    return 0;
}