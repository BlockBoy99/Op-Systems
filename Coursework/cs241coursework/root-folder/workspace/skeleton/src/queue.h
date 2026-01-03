#ifndef QUEUE_H
#define QUEUE_H

#include <pcap.h>
#include <pthread.h>

void init_queue();
void queue_shutdown(void);
void enqueue_packet(const struct pcap_pkthdr *hdr, const u_char *pkt, int verbose);
int dequeue_packet(struct pcap_pkthdr *hdr_out, u_char **pkt_out, int *verbose_out);

#endif
