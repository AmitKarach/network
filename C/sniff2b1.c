#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdio.h>
#define typeofloop -1 // Control type of Scan\Loop...

/* IP Header */ // Took from UNI
struct ipheader
{
    unsigned char iph_ihl : 4, iph_ver : 4;           //IP header length //IP version
    unsigned char iph_tos;                            //Type of service
    unsigned short int iph_len;                       //IP Packet length (data + header)
    unsigned short int iph_ident;                     //Identification
    unsigned short int iph_flag : 3, iph_offset : 13; //Fragmentation flags //Flags offset
    unsigned char iph_ttl;                            //Time to Live
    unsigned char iph_protocol;                       //Protocol type
    unsigned short int iph_chksum;                    //IP datagram checksum
    struct in_addr iph_sourceip;                      //Source IP address
    struct in_addr iph_destip;                        //Destination IP address
};
/* Ethernet header */ // Took from UNI
struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};
// Based off UNI Code - Main Fun to Recieve ICMP...
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_ICMP) // Only Attend to ICMP PACKETS
        {
            int ip_header_len = ip->iph_ihl * 4;
            struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ethheader) + ip_header_len);
            char *ip_src = inet_ntoa(ip->iph_sourceip); // Point to the Source Ip of the Packet
            printf("\nSorce IP: [%s] ", ip_src);
            char *ip_dest = inet_ntoa(ip->iph_destip); // Point to the Dest Ip of the Packet
            printf("Destination IP: [%s]\n", ip_dest);
            // Packet Type
            if ((icmph->type) == 8)
                printf("ICMP Type: Request\n");
            else
            {
                printf("ICMP Type: Reply\n");
            }
            printf("ICMP code: %d\n", icmph->code); // Code Data
        }
    }
}
int main() // Took From UNI
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "proto ICMP and (host 10.9.0.6 and 8.8.8.8)";
    bpf_u_int32 net;

    handle = pcap_open_live("br-c64184acb1a0", BUFSIZ, 1, 1000, errbuf); // Changed According to interface
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, typeofloop, got_packet, NULL); // Infinite Capture(cnt ==-1) Go to "got_packet"
    pcap_close(handle);                              //Close the handle
    return 0;
}
