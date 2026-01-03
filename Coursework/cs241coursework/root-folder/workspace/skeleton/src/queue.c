#include "queue.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MAX_QUEUE 1024
/*
 * Thread-safe bounded producer-consumer queue
 *
 * Producer threads: packet capture
 * Consumer threas: packet analysis workers
 * Synchronisation is achieved using mutex and condition variables
 * Has a graceful shutdown to unblock waiting threads
 * (I'm not writing this for every .c file)
*/


struct item { //Queue element containy a copy of packet and the metadata
    struct pcap_pkthdr hdr;
    u_char *pkt;
    int verbose;
};

static struct item queue[MAX_QUEUE];  //circular buffer implementation of a bounded queue

// Queue state variables
// front: index of next item to dequeue
// rear:  index of next slot to enqueue
// count: current number of items in queue
static int front = 0, rear = 0, count = 0;

static int shutdown_flag = 0; //indicates packet capture has finished and workers should exit

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;    //mutex protecting all sharef queue states
static pthread_cond_t not_empty = PTHREAD_COND_INITIALIZER; //signalled when queue goes from empty to not empty
static pthread_cond_t not_full  = PTHREAD_COND_INITIALIZER; //signalled when queue goes from full to not full
void init_queue() {
    //initialises queue state before threads start
    front = rear = count = 0;
}

void queue_shutdown() {
    pthread_mutex_lock(&lock);
    shutdown_flag = 1;  //signals all waiting threads to cleanly exit
    // wake ALL threads blocked on empty of full cinditions
    pthread_cond_broadcast(&not_empty);
    pthread_cond_broadcast(&not_full); 
    pthread_mutex_unlock(&lock);
}

void enqueue_packet(const struct pcap_pkthdr *hdr, const u_char *pkt, int verbose) { 
    //producer function, inserts packet into queue for later analysis
    //takes pointers to hdr, pkt and verbose outside function

    pthread_mutex_lock(&lock); //lock queue for exclusive access

    while (count == MAX_QUEUE && !shutdown_flag){ //check not max size and not shutting down
        pthread_cond_wait(&not_full, &lock); //wait until a consumer removes an item
    }
    if(shutdown_flag){
        pthread_mutex_unlock(&lock);//ensure not blocked forever and doesn't hang
        return;
    }
    queue[rear].hdr = *hdr; //store header
    queue[rear].pkt = malloc(hdr->caplen); //reserve enough space for packet
    memcpy(queue[rear].pkt, pkt, hdr->caplen); //deepy copy caplen bytes from pkt to queue item.pkt
    queue[rear].verbose = verbose; // store verbose int

    rear = (rear + 1) % MAX_QUEUE; //update queue indices and count
    count++;

    pthread_cond_signal(&not_empty); //signal at least one packet to analyse
    pthread_mutex_unlock(&lock); //unlock queue
}

int dequeue_packet(struct pcap_pkthdr *hdr_out, u_char **pkt_out, int *verbose_out) {
    //consumer function, removes a packet from queue
    //takes pointers to hdr, pkt and verbose outside function
    pthread_mutex_lock(&lock);

    while (count == 0 && !shutdown_flag ) //check not empty
        pthread_cond_wait(&not_empty, &lock); //realease lock while waiting on condition variable to change
    //note while used not if to avoid "spurious wakeups"
    if(shutdown_flag && count==0){
        //analysis has ended, signal worker thread to terminate
        pthread_mutex_unlock(&lock);
        return(0); //tell worker to exit
    }
    *hdr_out = queue[front].hdr; //store in pointer first packet header
    *pkt_out = queue[front].pkt;
    *verbose_out = queue[front].verbose;

    front = (front + 1) % MAX_QUEUE; //update queue indices and count
    count--;

    pthread_cond_signal(&not_full); //signal that queue may no longer be full
    pthread_mutex_unlock(&lock); //unlock queue
    return 1;
}


//rockon
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⡿⠿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠏⠀⠀⠀⠉⠛⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠐⣄⠀⠙⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⠀⠀⠈⣆⠀⠈⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣧⠀⠀⠀⠈⢣⠀⠈⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣧⠀⠀⠀⠈⠱⡀⠀⢻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⡈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣘⣷⣅⣀⡀⠀⠀⠙⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠉⠉⠉⠉⠉⠉⠀⠒⠒⠒⠲⠦⢤⣄⣀⡀⠀⠀⣀⡴⠖⠋⠉⠁⠀⠀⠀⠀⠀⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠙⢿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠉⠒⠂⠀⠀⢀⡀⠀⠀⠀⠈⠙⠳⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠈⠙⠛⠿⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠦⢤⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⡘⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠛⠛⠒⠒⠒⠒⢲⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢿⣿⣆⠹⣽⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⣾⠀⠀⠀⠀⠀⠀⣴⣿⡿⢶⡀⠀⠀⠀⠀⠀⠀⢻⣾⠿⣿⡆⠙⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⣾⠓⠒⠶⠦⢤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠁⠀⠀⠀⠀⢸⣿⣿⣧⣼⣷⠀⠀⠀⠀⠀⠀⠀⠻⠶⠟⠀⡼⢻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀
// ⠀⣿⠀⠀⠀⠀⠀⠀⠀⠈⡉⠙⠓⠲⠦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠘⢿⣅⣈⣿⠏⠀⠀⠀⠀⠶⠂⠀⠀⠀⠀⢠⡇⢨⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣶⣶⣷⣿⣿⣿⣿
// ⠀⢻⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠈⠉⠛⠲⢤⣄⡀⠀⠀⢹⡄⢀⡶⠛⠙⠳⣦⠉⠉⠁⠀⠀⠀⡀⠀⣀⣤⣤⠇⠀⠀⢸⣡⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣿⣿⣿⣯⣽⣳⣿⣿⡿⣹
// ⠀⢸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⢦⣀⢻⣼⡰⢄⠀⠀⠈⣧⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀⣠⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⣿⠿⠛⢉⡿⠉⠀
// ⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⠇⠹⣷⣀⠀⠀⢀⡿⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣰⣿⣿⣿⣀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣷⣿⣿⣿⣿⠿⢋⣁⣤⠾⠋⠀⠀⠀
// ⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⠀⢈⣿⠉⠉⠉⠀⠀⠀⣀⣀⣰⣦⣶⣾⡿⣻⣿⣿⣿⡟⠈⠙⢓⣦⣴⣾⣿⣿⣿⣿⣿⣿⠟⠛⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀
// ⠀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⢀⣴⣿⡇⠀⠀⠀⠀⢰⡿⢛⣛⣳⢽⣦⢀⣴⣿⣿⣿⠟⣀⣴⣞⣯⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠛⠁⠀⠀⠀⠀⠠⠤⠤⠤⠤⠤⠤⠤⣄⡀⠀⠀⠀⢠⡞⢀⣴⣿⣿⣿⡇⠀⠀⠀⠀⠘⡏⠉⠀⠈⠉⢻⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⡟⠋⠉⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣷⠃⠀⠀⠀⢈⣹⣿⣿⣿⣿⣿⣇⡂⠀⠀⠀⠀⣯⠀⠀⠀⣀⣿⣿⣻⣿⣿⣿⣿⣿⣿⣿⣛⣁⣀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⠀⠀⣀⣴⣿⣿⣿⣿⡿⠷⠷⣿⡘⠀⠀⠀⠀⣿⣦⣷⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠻⡍⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠇⠀⢀⡾⠛⠉⠁⠀⠀⠀⠀⠀⣾⣿⣧⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠠⡽⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠇⢀⢤⠞⡱⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣷⣄⣀⣤⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⢼⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⣿⢠⠇⠀⠀⠀⠀⠀⠀⢀⣴⣶⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣤⡤⣄⠀⠀⠀⠀⠀⠀⠲⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢸⠀⠀⠀⠀⠀⠀⠀⠸⣄⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡸⡄⠀⠀⠀⠀⠀⠀⠀⠙⢧⣨⠟⠁⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⢣⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⢀⣤⣿⣿⣿⣿⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⢧⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⠟⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢯⡳⡄⠀⠀⠀⣠⣾⣿⣽⡿⠛⢡⣾⠏⠀⠀⠀⢀⣀⣠⣤⠤⠤⠤⢤⢤⣀⠀⢀⣤⠾⣟⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠾⣶⣤⣀⡙⠾⠋⠁⢀⣠⡿⢃⣀⣤⠶⠛⠋⠉⠀⠀⠀⠀⠀⠙⢦⣀⠀⠀⢀⢀⣀⡻⠷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⠷⣶⣶⢿⣟⠋⣀⢄⣴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠲⠶⠦⠿⠷⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
// ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡋⣱⣏⣡⠽⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀