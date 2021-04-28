#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

// Required "includes" for SNIFF+SPOOF

// Basic Check Sum Function - has been used most of semester 
// Used forValidation and not for Fixing
unsigned short calc_chksm(unsigned short *packetadd, int length)
{
  int nleft = length;
  int sum = 0;
  unsigned short *y = packetadd;
  unsigned short answer = 0;
  while (nleft > 1)
  {
    sum += *y++;
    nleft -= 2;
  }
  if (nleft == 1)
  {
    *((unsigned char *)&answer) = *((unsigned char *)y);
    sum += answer;
  }
  
  sum = (sum >> 16) + (sum & 0xffff); 
  sum += (sum >> 16);                 
  answer = ~sum;                      
  return answer;
}
void send_reply(struct iphdr *ip)
{
  struct sockaddr_in dest_in;
  dest_in.sin_family = AF_INET;
  struct sockaddr_in dst;
  dst.sin_addr.s_addr = ip->daddr; 
  dest_in.sin_addr = dst.sin_addr;

  int sock;
  sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  //Sock Validity Check
  if (sock==-1)
  {
    printf("Sock Error");
    return; // Exit Func...
  }
// SetSock Requires this to be Const
  const int tempvar = 1;
  int setsockcheck = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &tempvar, sizeof(tempvar));
  // Validity check of SetSockOpt
  if (setsockcheck==-1)
  {
    printf("SetSock Failed");
    return;// Exit Func...
  }
  int senttocheck = sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
// SentTo Validity Check
  if ( senttocheck== -1)
  {
    printf("SendTo Failed");
    return;// Exit Func...
  }
// Obviously if all has been passed then spoof sucssesful 
  printf("The Packet Has Been Spoofed -- ");
  close(sock); // When Succsesful at end close Sock...
  return;// Exit Func...When Done!!
}
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *Buffer)
{
  struct iphdr *ip_h = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
  struct sockaddr_in src, dst;
  int ip_header_len = ip_h->ihl * 4;
  struct icmphdr *icmp_h = (struct icmphdr *)(Buffer + ip_header_len + sizeof(struct ethhdr));
  src.sin_addr.s_addr = ip_h->saddr; //Source Ip
  dst.sin_addr.s_addr = ip_h->daddr; //Destination IP

  char buffer[2000]; // Big Enough for us ...
  if ((int)(icmp_h->type) == 8)
  {
    printf("Spoofing - Packet.\n");
    memset(buffer, 0, 2000);
    //Recieve Data 
    u_char *pInfo = (u_char *)(Buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));
    int sizeofdata = ntohs(ip_h->tot_len) - (sizeof(struct iphdr)) + sizeof(struct icmphdr);
    memcpy((buffer + sizeof(struct iphdr) + sizeof(struct icmphdr)), pInfo, sizeofdata);
    //IP header STRCT
    struct iphdr *ip = (struct iphdr *)buffer;
    ip->version = 4;
    ip->ihl = ip_h->ihl;
    ip->ttl = 99;
    ip->saddr = inet_addr(inet_ntoa(dst.sin_addr));
    ip->daddr = inet_addr(inet_ntoa(src.sin_addr));
    ip->protocol = IPPROTO_ICMP; // in our Case Needed ICMP
    ip->tot_len = ip_h->tot_len;

    //ICMP header STRCT
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    icmp->type = 0; //ICMP Type: 8 is request, 0 is reply.
    icmp->un.echo.id = icmp_h->un.echo.id;
    icmp->un.echo.sequence = icmp_h->un.echo.sequence;
    icmp->checksum = 0; //Calculate the checksum
    icmp->checksum = calc_chksm((unsigned short *)icmp, sizeof(struct icmphdr) + sizeofdata);
    send_reply(ip);
  }
}





// Main driver 

int main()
{
  struct sockaddr_in src, dst;
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp"; // Pcap Filter - This is simple syntax to edit...
  bpf_u_int32 net;
  pcap_if_t *alldevsp, *device;
  pcap_t *handle; //Handle of the device that shall be sniffed
  char errorbuffprint[100], *reqinterface;
  reqinterface = "br-c64184acb1a0"; // My Task Interface via Docker...

  printf("Accessing Interface In Order to Sniff :");
  if (pcap_findalldevs(&alldevsp, errorbuffprint))
  {
    printf("Not Accessable");
    exit(1);
  }
  handle = pcap_open_live(reqinterface, BUFSIZ, 1, 1000, errorbuffprint);
  //Handle Validity Check
  if (handle == NULL)
  {
    printf("Handle Fail");
    exit(1);
  }
  // Begin Main Opertion
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp); // Filter...
  pcap_loop(handle, -1, process_packet, NULL); // Loop section for setting characteristics of sniff..
  pcap_close(handle); //Close the handle
  return 0;
}

