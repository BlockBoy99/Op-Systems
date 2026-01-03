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
#include <pthread.h>


#define MAX_ATTACKERS 1000
//This file is where you should put code to analyse packets and identify malicious packets. 
// The analyse() function should be called for each packet captured at the interface. 
// Currently the function does nothing. 
// Your code should analyse each packet to determine if the packet is malicious.
char attacker_ips[MAX_ATTACKERS][INET_ADDRSTRLEN];
int attacker_count=0;

static char **syn_ips = NULL;       // dynamically growing list of unique source ips sending TCP SYNs
static int syn_ips_count = 0;       // number of unique source IPs for syn attack
static int syn_total = 0;           // total number of SYN packets seen without ACK
static int syn_ips_capacity = 0;    // current capacity of syn_ips

static int arp_response_count = 0;  //number of arg response
static int google_blacklist=0;      // number of google blacklist violations
static int facebook_blacklist=0;    // number of facebool blacklist violations

pthread_mutex_t syn_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

//HELPER FUNCTIONS for safe packet parsing: CHeck each captured packet is correct size
// for expected headers Ethernet, IP, TCP and Payload.
int safe_ether_parse(const struct pcap_pkthdr *header) {
  return header->caplen >= sizeof(struct ether_header);
}
int safe_ip_parse(const struct pcap_pkthdr *header) {
  return header->caplen >= sizeof(struct ether_header) + sizeof(struct ip);
}
int safe_tcp_parse(const struct pcap_pkthdr *header, int ip_header_len) {
  return header->caplen >= sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr);
}
int safe_payload_parse(const struct pcap_pkthdr *header,
                      int ip_header_len,
                      int tcp_header_len) {
  int offset = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
  return header->caplen > offset;
}
//checks if source ip is already recorded for syn attack
int ip_exists(const char *ip){ 
  for(int i=0;i<syn_ips_count;i++){
    if(strcmp(syn_ips[i],ip)==0){ // ip in dyn array
      return(1);
    }
  }
  return(0);
}
//add a new source IP to syn_ips if not seen before
void add_ip(const char *ip) { 
    
  pthread_mutex_lock(&syn_lock);
  if (!ip_exists(ip)) {
    if (syn_ips_count == syn_ips_capacity) {
      int new_capacity = syn_ips_capacity == 0 ? 1024 : syn_ips_capacity * 2;
      char **new_list = realloc(syn_ips, new_capacity * sizeof(char *));
      if (!new_list) {
        pthread_mutex_unlock(&syn_lock);
        return;
      }
      syn_ips = new_list;
      syn_ips_capacity = new_capacity;
    }
    syn_ips[syn_ips_count] = malloc(INET_ADDRSTRLEN);
    strcpy(syn_ips[syn_ips_count], ip);
    syn_ips_count++;
  }
  pthread_mutex_unlock(&syn_lock);
}

//INTRUSION DETECTION functions
//Check syn flooding with SYN set and ACK not set
void check_syn_flood(struct pcap_pkthdr *header,
                    const unsigned char *packet, 
                    int verbose){
  if(!safe_ether_parse(header)){
    return; //packet truncated
  }
  //check eth header for ip type
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { return;}//not IPV4

  if(!safe_ip_parse(header)){
    return;//packet truncated
  }
  //check ip header for protocol
  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));  //move pointer past eth header to ip header
  if(ip_hdr->ip_p!=IPPROTO_TCP){ //not TCP
    return;
  }

  int ip_header_len=ip_hdr->ip_hl *4; //ip header length in 32 bit words converted to bytes (4 bytes per 32 bit word)
  
  if(!safe_tcp_parse(header,ip_header_len)){
    return;//truncation
  }
  struct tcphdr *tcp_hdr=(struct tcphdr *) (packet +sizeof(struct ether_header)+ip_header_len); //move pointer to tcp hdr
  
  if((tcp_hdr->th_flags & TH_SYN) && 
  !(tcp_hdr->th_flags & TH_ACK)){ //check control flags and that they are bitwise AND to correct flags
    //packet is part of syn flood
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN); //convert source ip to readable string

    pthread_mutex_lock(&syn_lock);
    syn_total++;
    pthread_mutex_unlock(&syn_lock);

    //attempt to add to list of unique blacklist ips
    add_ip(src_ip);

    if(verbose){
      char target_ip[INET_ADDRSTRLEN]; 
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), target_ip, INET_ADDRSTRLEN); //convert target ip to readable string
      printf("SYN attack detected\nSource IP address: %s\nTarget IP address: %s\n",src_ip,target_ip);
    }
  }
}
//identifies ARP responses (op=2)
void check_ARP_poisoning(struct pcap_pkthdr *header,
                        const unsigned char *packet, 
                        int verbose){ 

  
  //check eth header for ETH_P_ARP
  if(!safe_ether_parse(header)){
    return;//truncation
  }
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header
  if (ntohs(eth_header->ether_type) != ETH_P_ARP) {  //defined in if_ether.h>
      return;
  }

  struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
  if(ntohs(arp->ea_hdr.ar_op)==ARPOP_REPLY){ //check is an ARP response not just request
    pthread_mutex_lock(&stats_lock);
    arp_response_count++; 
    pthread_mutex_unlock(&stats_lock);
    if(verbose){
      // source info
      char src_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, arp->arp_spa, src_ip, INET_ADDRSTRLEN);
      // same for target
      char target_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, arp->arp_tpa, target_ip, INET_ADDRSTRLEN);
      printf("ARP response detected: %s -> %s\n", src_ip, target_ip);
    }
  }
  
  
}

// struct	ether_arp {
// 	struct	arphdr ea_hdr;	/* fixed-size header */
// 	u_char	arp_sha[ETHER_ADDR_LEN];	/* sender hardware address */
// 	u_char	arp_spa[4];	/* sender protocol address */
// 	u_char	arp_tha[ETHER_ADDR_LEN];	/* target hardware address */
// 	u_char	arp_tpa[4];	/* target protocol address */
// };
//inspect HTTP traffic on TCP port 80
void check_blacklisted_urls(struct pcap_pkthdr *header,
                            const unsigned char *packet, 
                            int verbose){ 
  if(!safe_ether_parse(header)){
    return;//truncation
  }
  struct ether_header *eth_header = (struct ether_header *) packet;//casts first part of packet to ETHERNET header
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
      return; //not ip packet
  }
  if(!safe_ip_parse(header)){
    return;//truncation
  }
  //check ip header for protocol
  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));  //move pointer past eth header to ip header
  if(ip_hdr->ip_p!=IPPROTO_TCP){
    return; // not TCP
  }

  
  // TCP header
  int ip_header_len=ip_hdr->ip_hl *4; //ip header length in 32 bit words converted to bytes (4 bytes per 32 bit word)
  if(!safe_tcp_parse(header,ip_header_len)){
    return;//malformed packet
  }
  struct tcphdr *tcp_hdr=(struct tcphdr *) (packet +sizeof(struct ether_header)+ip_header_len); //move pointer to tcp hdr
  if(!(ntohs(tcp_hdr->th_sport)==80 || ntohs(tcp_hdr->th_dport)==80)){ //try tcp_hdr->th_sport and th_dport
    //HTTP traffic not detected on(TCP port 80)
    return;
  }

  int tcp_header_len = tcp_hdr->th_off * 4;

  //payload length and bounds check
  if(!safe_payload_parse(header,ip_header_len,tcp_header_len)){
    return; 
  }
  int payload_len = header->caplen - (sizeof(struct ether_header) + ip_header_len + tcp_header_len);

  //copy payload safely
  char payload_buf[2048];
  int copy_len = payload_len < 2047 ? payload_len : 2047;
  memcpy(payload_buf, packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len, copy_len);
  payload_buf[copy_len] = '\0';

  char *host_ptr = strcasestr(payload_buf, "Host:"); 
  if (!host_ptr){                                         //check there is a host in payload
    return;
  }
  char host[256];
  if (sscanf(host_ptr, "Host: %255s", host) != 1) return; //check there is a host name after
  char *newline = strpbrk(host, "\r\n");                  //scan for first occurence of \r and \n after host id
  if (newline) *newline = '\0';                           //if occurence found, replace it

  // Determine if host is blacklisted
  int is_blacklisted = 0;
  char *domain_name = NULL;
  if (strcmp(host, "www.google.co.uk") == 0 || strcmp(host, "google.co.uk") == 0) {
      pthread_mutex_lock(&stats_lock);
      google_blacklist++;
      pthread_mutex_unlock(&stats_lock);
      is_blacklisted = 1;
      domain_name = "google";
  } else if (strcmp(host, "www.facebook.com") == 0 || strcmp(host, "facebook.com") == 0) {
      pthread_mutex_lock(&stats_lock);
      facebook_blacklist++;
      pthread_mutex_unlock(&stats_lock);
      is_blacklisted = 1;
      domain_name = "facebook";
  }

  if(is_blacklisted){ //output details
    char src_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), target_ip, INET_ADDRSTRLEN);
    
    printf("==============================\n");
    printf("Blacklisted URL violation detected\n");
    printf("Source IP address: %s\n", src_ip);
    printf("Destination IP address: %s (%s)\n", target_ip, domain_name);
    printf("==============================\n");
  }
}
//start per-packet analysis. Each detection system is independent
void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) { 
  check_syn_flood(header,packet, verbose);
  check_ARP_poisoning(header,packet, verbose);
  check_blacklisted_urls(header,packet,verbose);
}
// on close output intrusion detect report and frees allocated resources
void analysis_cleanup(){ 
    printf("\nIntrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n", syn_total, syn_ips_count);
    printf("%d ARP responses (cache poisoning)\n",arp_response_count);
    printf("%d URL Blacklist violations (%d google and %d facebook)\n",(google_blacklist+facebook_blacklist),google_blacklist,facebook_blacklist);

    // Free memory
    for (int i = 0; i < syn_ips_count; i++)
        free(syn_ips[i]);
    free(syn_ips);
}