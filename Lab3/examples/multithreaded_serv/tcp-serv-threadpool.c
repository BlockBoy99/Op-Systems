#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include "queue.h"

#define BUFSIZE 2048
#define BACKLOG 500
#define NUMTHREADS 10
#define PORTNO 9999


/* Queue where the main server thread adds work and from where the
worker threads pull work*/
struct queue *work_queue;
int servSocket; // socket for accepting new requests. declared global to allow access by signal handler

/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queue_cond=PTHREAD_COND_INITIALIZER;

volatile int loop=1; //variable to determine if to continue the threads based on received signal

void handler(int signal){
	loop=0; // setting loop to 0 stops new request from being accepted but continues the workers until the work in the queue is finished 
	close(servSocket);  //closes server socket to wake up the main thread from blocking accept(). Note that close() is async signal safe.
}



/*Function to be executed by each worker thread*/
void *handle_conn(void *arg){
	int recvlen;
	int conn_sock;
	char buf[BUFSIZE];
	long long limit;
	long long sum=0,i;

	/* In a loop continue checking if any more work is left to be done*/
	while(loop||!isempty(work_queue)){

		// acquire lock, get connection socket descriptor from work queue, release lock
		// wait if work queue is empty
		pthread_mutex_lock(&queue_mutex);
		while(isempty(work_queue)&&loop==1){
			pthread_cond_wait(&queue_cond,&queue_mutex);
		}
		if(!isempty(work_queue)){
			conn_sock=work_queue->head->item;
			dequeue(work_queue);
			pthread_mutex_unlock(&queue_mutex);


			// read from connetion socket into buffer
			recvlen = read(conn_sock, &limit, sizeof(limit));

			// print received message
			if (recvlen > 0) {
				printf("Received number by thread %d: %lld\n", (int)pthread_self(), limit);
			}
			else{
				printf("uh oh - something went wrong!\n");
			}

			sum=0;
			for(i=1;i<=limit;i++){ //compute the sum
				sum+=i;
			}
			// send back to the sender by writing to the conneection socket
			write(conn_sock,&sum,sizeof(sum));
			printf("Sent sum %lld. Keeping worker alive..\n",sum);
		}
		else{
			pthread_mutex_unlock(&queue_mutex);
		}
	}
	printf("Worker Terminating..\n");
	return NULL;
}

int main(int argc, char **argv)
{
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
  	int conn_sock;             /* connection specific socket */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	// int servSocket;				/* our socket */
	int msgcnt = 0;			/* count # of messages we received */
	char buf[BUFSIZE];	/* receive buffer */
	int *sock_ptr;
	int i;
	pthread_t tid[NUMTHREADS]; // array to store thread id's
	unsigned short port_num=PORTNO;

	signal(SIGINT,handler);


	//create work queue
	work_queue=create_queue();


	//create the worker threads
	for(i=0;i<NUMTHREADS;i++){
		pthread_create(&tid[i],NULL,handle_conn,NULL);
	}

	/* create a TCP socket */

	if ((servSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("Error: cannot create socket\n");
		exit(1);
	}

	/* bind the socket to any valid IP address and a specific port */

	memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(port_num);

	if (bind(servSocket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		printf("Error: bind failed\n");
		exit(1);
	}

	// start listening on the created port for incoming connections
	// the second parameter "BACKLOG" specifies the max number of connections that can
	// wait in a queue to get accepted
	listen(servSocket,BACKLOG);
	printf("waiting on port %d\n",port_num);


	/* now loop, accepting incoming connections and adding them to the work queue */
	while (loop){

		// accept incoming connection request and create connection specific socket

        	conn_sock=accept(servSocket,(struct sockaddr *)&remaddr, &addrlen);

		if (loop){
			// acquire lock, add connection socket to the work queue,
			// signal the waiting threads, and release lock
			pthread_mutex_lock(&queue_mutex);
			enqueue(work_queue,conn_sock);
			pthread_cond_broadcast(&queue_cond);
			pthread_mutex_unlock(&queue_mutex);
		}
		else{
			pthread_cond_broadcast(&queue_cond); // wakes up the workers so that they can properly finish
		}
	}
	for(i=0;i<NUMTHREADS;i++){
		pthread_join(tid[i],NULL); //the main thread joins with the workers
	}
	destroy_queue(work_queue); // queue is deallocated
	printf("Main server terminating..\n");
  return 0;
}
