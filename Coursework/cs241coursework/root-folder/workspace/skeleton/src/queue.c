#include "queue.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE 1024

struct item {
    struct pcap_pkthdr hdr;
    u_char *pkt;
    int verbose;
};

static struct item queue[MAX_QUEUE];
static int front = 0, rear = 0, count = 0;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void init_queue() {
    front = rear = count = 0;
}

void enqueue_packet(const struct pcap_pkthdr *hdr, const u_char *pkt, int verbose) {
    //takes pointers to hdr, pkt and verbose to store outside queue
    pthread_mutex_lock(&lock); //lock queue

    while (count == MAX_QUEUE) //check not max size
        pthread_cond_wait(&cond, &lock); //realease lock while waiting on condition variable

    queue[rear].hdr = *hdr; //store header
    queue[rear].pkt = malloc(hdr->caplen); //reserve enough space for packet
    memcpy(queue[rear].pkt, pkt, hdr->caplen); //copy caplen bytes from pkt to queue item.pkt
    queue[rear].verbose = verbose; // store verbose int

    rear = (rear + 1) % MAX_QUEUE; //update queue indices and count
    count++;

    pthread_cond_signal(&cond); //signal at least one packet to analyse
    pthread_mutex_unlock(&lock); //unlock queue
}

int dequeue_packet(struct pcap_pkthdr *hdr_out, u_char **pkt_out, int *verbose_out) {
    //takes pointers to hdr, pkt and verbose to store outside queue
    pthread_mutex_lock(&lock);

    while (count == 0) //check not empty
        pthread_cond_wait(&cond, &lock); //realease lock while waiting on condition variable to change

    *hdr_out = queue[front].hdr; //store in pointer first packet header
    *pkt_out = queue[front].pkt;
    *verbose_out = queue[front].verbose;

    front = (front + 1) % MAX_QUEUE; //update queue indices and count
    count--;

    pthread_cond_signal(&cond); //signal that queue may no longer be full
    pthread_mutex_unlock(&lock); //unlock queue
    return 1;
}