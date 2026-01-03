#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <signal.h>

#include "dispatch.h"
#include "analysis.h"
#include "queue.h"

#define NUM_WORKERS 20 //define workers according to cores

pthread_t workers[NUM_WORKERS];
static volatile sig_atomic_t stop_flag = 0;
static pcap_t *pcap_handle = NULL;

//Worker thread loop function
//continuously deques packets from shared queue
// analyses them and frees from memory when done
//closes when dequeu_packet() returns False
//so when shutdown initiated and queue is empty
void *worker_loop(void *arg) {
  struct pcap_pkthdr hdr;
  u_char *pkt;
  int verbose;

  while (dequeue_packet(&hdr, &pkt, &verbose)) {
      //; //dequeue packet
      analyse(&hdr, pkt, verbose);          //analyse packet
      free(pkt);                            //free the packet when done
  }
  return NULL;
}
//Signal handle for SIGINT Ctrl-C
//set stops flag so threads stop and break pcap capture loop
void handle_sigint(int sig) {
    (void)sig;
    stop_flag = 1;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle); // safe
    }
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  char errbuf[PCAP_ERRBUF_SIZE];

  signal(SIGINT, handle_sigint);
  init_queue(); //initialises queue

  // Start Intrusion Detection System
  for (int i = 0; i < NUM_WORKERS; i++) {
    pthread_create(&workers[i], NULL, worker_loop, NULL);
  }

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  pcap_loop(pcap_handle, -1, dispatch, (u_char*) &verbose);


  printf("\nStopping capture...\n");
  
  queue_shutdown();    //wake all worker threads
  for (int i = 0; i < NUM_WORKERS; i++) { //join worker threads
    pthread_join(workers[i], NULL);
  }
  // calls cleanup function in analysis.c#
  analysis_cleanup();  
  //close pcap
  pcap_close(pcap_handle);
  pcap_handle=NULL;
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) { //removed as only for debugging but can be easily called by adding code that if verbose, call dump
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  unsigned short ethernet_type=ntohs(eth_header->ether_type);
  printf("Actual Type: %hu\n", ethernet_type);
  if(ethernet_type==2054){
    printf("is actually: ARP");
  } else if(ethernet_type==2048){
    printf("is actually: IPV4");
  } else if(ethernet_type==36866){
    printf("is actually: TCP/IP compression");
  } else if(ethernet_type==34667){
    printf("is actually: TCP-IP sys");
  } 
  else{
    printf("Lowkey idk what type");
  }
  printf("\n === PACKET %ld DATA == \n", pcount);

  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
