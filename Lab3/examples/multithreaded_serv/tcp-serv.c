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

#define BUFSIZE 2048
#define BACKLOG 500
#define PORTNO 9999


int servSocket; // socket for accepting new connections. declared as global to allow access by the signal handler
volatile int loop=1; // variable that determines if to continue looping based on reception of signal

/*Function to be executed by each thread*/
void *handle_conn(void *arg){
	int recvlen;
	int conn_sock=*((int *)arg); // copy the value stored in arg
	char buf[BUFSIZE];
	long long limit;
	long long sum=0,i;


	// free the allocated memory
	free(arg);

	//read from connection socket into buf
	recvlen = read(conn_sock, &limit, sizeof(limit));

	// print received message		
	if (recvlen > 0) {
		printf("received number: %lld\n", limit);
	}
	else{
		printf("uh oh - something went wrong!\n");
	}

	//limit=atoll(buf); // convert received text into a long long number

	
	for(i=1;i<=limit;i++){ //compute the sum
		sum+=i;
	}

	// send back sum to the sender by writing to the connection socket
	write(conn_sock,&sum,sizeof(sum)); 
	
	printf("Sent sum %lld. Now terminating worker..\n",sum);
	return NULL;

}

void signal_handler(int signal){

	loop=0;            // the value of loop changes to indicate that the main server loop should discontinue
	close(servSocket); // close() is async signal safe and wakes up the main thread by closing the socket on which it was blocked
}

int main(int argc, char **argv)
{
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
    int conn_sock;			/* connection specific socket */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	//int servSocket;				/* our socket */
	int msgcnt = 0;			/* count # of messages we received */
	char buf[BUFSIZE];	/* receive buffer */
	int *sock_ptr;
	int i;
	pthread_t tid;
	unsigned short port_num=PORTNO;

	signal(SIGINT,signal_handler);

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

	/* now loop, receiving connections and handing them over to threads for processing */

	while (loop) {

		//accept an incoming connection and create a connection socket
		//specific to the accepted connection

	        conn_sock=accept(servSocket,NULL, NULL);

		if(loop){

			/*instead of passing the address of the file descriptor for the connection socket to the thread
			it is better to pass its value so that different threads don't write to this address
			simultaneously. So we malloc some memory and store the connection socket's descriptor there
			and pass the address of this dynamically created block */

			sock_ptr=(int *)malloc(sizeof(int));
			*sock_ptr=conn_sock;

			//pass the connection socket file descriptor to the thread handling the connection
			pthread_create(&tid,NULL,handle_conn,(void *)sock_ptr);
			//detach the new thread from the main thread so that OS can deallocate the resources given to it when the thread finishes without the main thread joining with it
			pthread_detach(tid);
		}
	}
    return 0;
}
