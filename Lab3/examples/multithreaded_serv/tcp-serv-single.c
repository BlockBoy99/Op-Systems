#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>

#define BUFSIZE 2048
#define BACKLOG 500
#define PORTNO 8888


/*Function to be executed by each thread*/
void handle_conn(int sock){
	int recvlen;
	long long limit;
	long long sum=0,i;



	//read from connection socket into buf
	recvlen = read(sock, &limit, sizeof(limit));

	// print received number		
	if (recvlen > 0) {
		printf("received number: %lld\n", limit);
	}
	else{
		printf("uh oh - something went wrong!\n");
	}

	
	for(i=1;i<=limit;i++){ //compute the sum
		sum+=i;
	}

	// send back sum to the sender by writing to the connection socket
	write(sock,&sum,sizeof(sum)); 
	
	printf("Sent sum %lld. Now terminating thread.\n",sum);

}

int main(int argc, char **argv)
{
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
    int conn_sock;			/* connection specific socket */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int servSocket;				/* our socket */
	int msgcnt = 0;			/* count # of messages we received */
	char buf[BUFSIZE];	/* receive buffer */
	int *sock_ptr;
	int i;
	pthread_t tid;
	unsigned short port_num=PORTNO;


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

	while (1) {

		//accept an incoming connection and create a connection socket
		//specific to the accepted connection

        conn_sock=accept(servSocket,NULL, NULL);

        handle_conn(conn_sock);
	}
    return 0;
}
