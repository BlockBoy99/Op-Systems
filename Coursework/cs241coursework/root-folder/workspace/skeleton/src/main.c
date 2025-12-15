#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"
#include <pthread.h>
// Command line options
#define OPTSTRING "vi:"
static struct option long_opts[] = {
  {"interface", optional_argument, NULL, 'i'},
  {"verbose",   optional_argument, NULL, 'v'}
};

struct arguments {
  char *interface;
  int verbose;
};

pthread_t worker;

void *worker_loop(void *arg) {
    struct pcap_pkthdr hdr;
    u_char *pkt;
    int verbose;

    while (1) {
        dequeue_packet(&hdr, &pkt, &verbose); //dequeue packet
        analyse(&hdr, pkt, verbose); //analyse packet
        free(pkt); //free the packet when done
    }
  return NULL;
}

void handle_sigint(int sig) {
    printf("\nStopping capture...\n");
    analysis_cleanup();  // calls cleanup function in analysis.c
    exit(0);             // terminate program
}



void print_usage(char *progname) {
  fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
  fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
  fprintf(stderr, "\t-i [interface]\tSpecify network interface to sniff\n");
  fprintf(stderr, "\t-v\t\tEnable verbose mode. Useful for Debugging\n");
}

pthread_t worker_thread;
int main(int argc, char *argv[]) {
  signal(SIGINT, handle_sigint);
  // Parse command line arguments
  struct arguments args = {"eth0", 0}; // Default values
  int optc;
  while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF) {
    switch (optc) {
      case 'v':
        args.verbose = 1;
        break;
      case 'i':
        args.interface = (optarg);
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  // Print out settings
  printf("%s invoked. Settings:\n", argv[0]);
  printf("\tInterface: %s\n\tVerbose: %d\n", args.interface, args.verbose);
  // Invoke Intrusion Detection System
  init_queue();
  pthread_create(&worker_thread, NULL, worker_loop, NULL);
  sniff(args.interface, args.verbose);
  return 0;
}
