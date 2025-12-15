#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H
#include "queue.h" 
#include <pcap.h>
void dispatch(u_char *user,
              const struct pcap_pkthdr *header,
              const u_char *packet);
// void dispatch(struct pcap_pkthdr *header, 
//               const unsigned char *packet,
//               int verbose);

#endif
