#include "analysis.h"

#define _GNU_SOURCE

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>


#define MAX_ATTACKERS 1000
//This file is where you should put code to analyse packets and identify malicious packets. 
// The analyse() function should be called for each packet captured at the interface. 
// Currently the function does nothing. 
// Your code should analyse each packet to determine if the packet is malicious.
char attacker_ips[MAX_ATTACKERS][INET_ADDRSTRLEN];
int attacker_count=0;

static char **syn_ips = NULL;       // dynamically growing list of strings
static int syn_ips_count = 0;       // number of unique source IPs for syn attack
static int syn_total = 0;           // total number of SYN packets seen

static int arp_response_count = 0;       //number of arg response

static int google_blacklist=0;
static int facebook_blacklist=0;

int ip_exists(const char *ip){ //checks if ip is recorded
  for(int i=0;i<syn_ips_count;i++){
    if(strcmp(syn_ips[i],ip)==0){ // ip in dyn array
      return(1);
    }
  }
  return(0);
}
void add_ip(const char *ip){
  if (ip_exists(ip)) // ip already recorded
        return;
  syn_ips=realloc(syn_ips,(syn_ips_count+1)*sizeof(char *)); //expand array by one pointer
  syn_ips[syn_ips_count]=malloc(INET_ADDRSTRLEN); // allocates memory for ip string
  strcpy(syn_ips[syn_ips_count],ip);
  syn_ips_count++;
}
void check_syn_flood(struct pcap_pkthdr *header,const unsigned char *packet, int verbose){
  //Check syn flooding

  //check eth header for ip type
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
      //printf("Not IPV4\n");
      return;
  }
  printf("Ethertype: 0x%04x\n", ntohs(eth_header->ether_type));

  //check ip header for protocol
  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));  //move pointer past eth header to ip header
  if(ip_hdr->ip_p!=IPPROTO_TCP){
    //printf("Not TCP");
    return;
  }

  int ip_header_len=ip_hdr->ip_hl *4; //ip header length in 32 bit words converted to bytes (4 bytes per 32 bit word)
  struct tcphdr *tcp_hdr=(struct tcphdr *) (packet +sizeof(struct ether_header)+ip_header_len); //move pointer to tcp hdr

  if((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK)){ //check control flags and that they are bitwise AND to correct flags
    syn_total++; //packet is part of syn flood
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN); //convert source ip to readable string

    add_ip(src_ip); //attempt to add to list of unique blacklist ips
    printf("SYN flooding detected\n");

    char target_ip[INET_ADDRSTRLEN]; //target ip read
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), target_ip, INET_ADDRSTRLEN);


    printf("Source IP address: %s\n",src_ip);
    printf("Target IP address: %s\n", target_ip);  //IS NOT IP
  }
}
void check_ARP_poisoning(struct pcap_pkthdr *header,const unsigned char *packet, int verbose){
  //check for arp packet

  //check eth header for ETH_P_ARP
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header
  if (ntohs(eth_header->ether_type) != ETH_P_ARP) {  //defined in if_ether.h>
      return;
  }
  printf("ARP packet detected\n");
  printf("Ethertype: 0x%04x\n", ntohs(eth_header->ether_type));

  struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

  // source info
  char src_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, arp->arp_spa, src_ip, INET_ADDRSTRLEN);
  // same for target
  char target_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, arp->arp_tpa, target_ip, INET_ADDRSTRLEN);

  printf("Source IP address: %s\n", src_ip);
  printf("Target IP address: %s\n", target_ip);  //IS NOT IP
  arp_response_count++; 
}
// struct	ether_arp {
// 	struct	arphdr ea_hdr;	/* fixed-size header */
// 	u_char	arp_sha[ETHER_ADDR_LEN];	/* sender hardware address */
// 	u_char	arp_spa[4];	/* sender protocol address */
// 	u_char	arp_tha[ETHER_ADDR_LEN];	/* target hardware address */
// 	u_char	arp_tpa[4];	/* target protocol address */
// };

void check_blacklisted_urls(struct pcap_pkthdr *header,const unsigned char *packet, int verbose){
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header

  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
      printf("Not IP packet!\n");
      return;
  }
  printf("Ethertype: 0x%04x\n", ntohs(eth_header->ether_type));

  //check ip header for protocol
  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));  //move pointer past eth header to ip header
  if(ip_hdr->ip_p!=IPPROTO_TCP){
    return;
  }

  int ip_header_len=ip_hdr->ip_hl *4; //ip header length in 32 bit words converted to bytes (4 bytes per 32 bit word)
  struct tcphdr *tcp_hdr=(struct tcphdr *) (packet +sizeof(struct ether_header)+ip_header_len); //move pointer to tcp hdr
  if(!(ntohs(tcp_hdr->th_sport)==80 || ntohs(tcp_hdr->th_dport)==80)){ //try tcp_hdr->th_sport and th_dport
    printf("HTTP traffic not detected on(TCP port 80)\n");
    return;
  }
  printf("HTTP traffic detected (TCP port 80)\n");
  int tcp_header_len = tcp_hdr->th_off * 4;

  const char *payload = (const char *)(packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len);
  int payload_len = header->len - (sizeof(struct ether_header) + ip_header_len + tcp_header_len);
  if(payload_len<0){
    printf("No payload");
    return;
  }
  char *host_ptr = strcasestr(payload, "Host:");
  if (host_ptr) {
      if (strcasestr(host_ptr, "google.com") ||
          strcasestr(host_ptr, "google.co.uk")){
            google_blacklist++;
            printf("Blacklisted domain detected: %s\n", host_ptr);
      }
     
      if(strcasestr(host_ptr, "facebook.com")){
        facebook_blacklist++;
        printf("Blacklisted domain detected: %s\n", host_ptr);
      } 
      char src_ip[INET_ADDRSTRLEN];
      char target_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), target_ip, INET_ADDRSTRLEN);
      printf("Source IP: %s\n", src_ip);  //IS NOT IP
      printf("Target IP: %s\n", target_ip);  //IS NOT IP

  }
}
void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

  check_syn_flood(header,packet, verbose);
  check_ARP_poisoning(header,packet, verbose);
  check_blacklisted_urls(header,packet,verbose);
}
void analysis_cleanup(){ // on close reports intrusion detection for syn
    printf("\nIntrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n",
           syn_total, syn_ips_count);

    // Your assignment’s required other counters:
    printf("%d ARP responses (cache poisoning)\n",arp_response_count);
    printf("%d URL Blacklist violations (%d google and %d facebook)\n",(google_blacklist+facebook_blacklist),google_blacklist,facebook_blacklist);

    // Free memory
    for (int i = 0; i < syn_ips_count; i++)
        free(syn_ips[i]);
    free(syn_ips);
}

//Temp dump function
