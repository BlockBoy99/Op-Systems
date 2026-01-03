Source files found in: Coursework/cs241coursework/root-folder/workspace/skeleton/src

My project solution overview:
This program uses a producer-consumer threading model with a thread pool to allow 
packet analysis even under high traffic. Packet capture is performed by the sniff() 
function via pcap_loop() whilst analysis is done by separate worker threads. 
The dispatch() function acts as the producer in this model. Each captured packet is 
safely copied and enqueued into a fixed-size shared queue implemented in queue.c. 
Worker threads continuously dequeue packets (assuming the queue is not empty) and 
perform analysis via calls to the analyse( ) function in analysis.c. 
The analyse() function performs multiple detection checks on each packet, including 
identification of SYN floods, ARP cache poisoning attempts, and access to blacklisted 
URLs. To ensure thread safety, all shared counters and dynamically allocated data 
structures are protected using mutexes, so that two threads don’t update the data at 
the same time 
Shutdown is handled gracefully: when a SIGINT (Ctrl+C) is received, packet capture is 
stopped using pcap_breakloop(), the queue is emptied fully by worker threads, and 
resources are cleaned up safely. This ensures that no captured packets are lost and all 
analysis statistics are accurate.
