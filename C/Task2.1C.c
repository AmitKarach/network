#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h> //contain the ethernet header
#include <netinet/ip.h>	//contain the ip header
#include <netinet/tcp.h> // contain the tcp header
#include <linux/if_ether.h>

#define typeofloop -1 // Control type of Scan\Loop...





void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
  int size_of_data= 0;
  
  struct iphdr* ip_h = (struct iphdr*)(packet +sizeof(struct ethhdr));
  struct sockaddr_in src,dst;
  int ip_header_len = ip_h->ihl * 4;  
  struct tcphdr * tcp_h = (struct tcphdr *)(packet + ip_header_len + sizeof(struct ethhdr));
  
  
  src.sin_addr.s_addr = ip_h->saddr;
  dst.sin_addr.s_addr = ip_h->daddr;
	
  
  //get the data part/payload in the packet 
  char *packet_data = (char *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
 
  //data size=tot_len - ip heder size + tcp heder size
  size_of_data = ntohs(ip_h->tot_len) - (sizeof(struct iphdr)) + sizeof(struct tcphdr) ;
 
  // here we are printing the information of the packet.
  if(ip_h->protocol == IPPROTO_TCP && ntohs(tcp_h->th_dport) == 23)
   {
     printf("tcp information: \n the source is %d\n the destanation is: %d\n",ntohs(tcp_h->th_sport),ntohs(tcp_h->th_dport));
     printf("source ip is: %s \n", inet_ntoa(src.sin_addr));
     printf("destanation ip is: %s \n",inet_ntoa(dst.sin_addr));
  
  //here we are printing the data 
  printf("%d",size_of_data);
  if(size_of_data > 0)
  {
      printf("the packet data is:\n");
      for(int i = 0 ; i < size_of_data; i++)
       {
        if(isprint(*packet_data))
          {printf("%c",*packet_data);}
        else
          {printf("_");}
        packet_data++;
      }
    printf("\n\n");
   }
}
}
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  
  
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("br-c64184acb1a0", BUFSIZ, 1, 1000, errbuf); 

  
  pcap_compile(handle, &fp, filter_exp, 0, net);     
  pcap_setfilter(handle, &fp);
  

  pcap_loop(handle,typeofloop,got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}