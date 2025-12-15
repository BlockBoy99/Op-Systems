#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"
#include <netinet/if_ether.h>

// void dispatch(struct pcap_pkthdr *header,
//               const unsigned char *packet,
//               int verbose) {
//   // TODO: Your part 2 code here
//   // This method should handle dispatching of work to threads. At present
//   // it is a simple passthrough as this skeleton is single-threaded.

//   analyse(header, packet, verbose);
// }

void dispatch(u_char *user, const struct pcap_pkthdr *header,
              const u_char *packet) {

    int verbose = *(int *)user; //retrieve verbose correctly

    // Instead of calling analyse directly,
    // enqueue packet for worker threads
    enqueue_packet(header, packet, verbose);
}
