/*
        demo-udp-03: udp-recv: a simple tcp server
	receive udp messages

        usage:  tcp-recv
*/

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
#define PORTNO 8888

unsigned long long sum_upto(unsigned long long n){
	__int128 s=(__int128)n*(n+1)/2;
	return(unsigned long long)s;
}
int main(int argc, char **argv){
	struct sockaddr_in myaddr;	/* struct variable to store the address of server */
	struct sockaddr_in remaddr;	/* struct variable to store the address of client */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # of bytes received */
	int servSocket;				/* file descriptor for the server socket */
	int conn_sock;           /* file descriptor for connection socket, needed because we are using TCP */
	int msgcnt = 0;			/* count # of messages we received */
	char buf[BUFSIZE];	    /* receive buffer to store the received message */
	int i;
	unsigned short port_num=PORTNO;


	/* create a TCP socket, if not successful, exit with error message.
	The first argument AF_INET of socket() specifies that the socket
	is going to use IPv4 addresses, the next argument SOCK_STREAM specifies 
	that the type of the socket is TCP, the last argument is for protocol family
	and is set to 0 in most applications. see the man page of socket(). */

	if ((servSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("Error: cannot create socket\n");
		exit(1);
	}

	/* Fill up the different fields of the struct variable myaddr with relevant information so
	   that it can be used as a valid address for the server socket */

	//memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	myaddr.sin_port = htons(port_num);

	
	/* bind the socket to the specific IP address and port above. This gives the server
	a specific IP and port number which can be used by clients to
	connect to the server. Note that the socket() call assigns a random port number to the socket
	but we want to use a specific port number at the server, that's why bind() is required on the server side.*/
	
	if (bind(servSocket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		printf("Error: bind failed\n");
		exit(1);
	}


	/* now loop, receiving data and printing what we received */
	while (1) {
		printf("waiting on port %d\n",port_num);

		/* Calling listen() on the server socket makes the server socket listen for new incoming connection requests.
		The second argument in the call specifies the limit on the maximum number of pending connection.
		If this case, we set to zero to to say that there should not be any pending connection.
		See the man page of listen()*/

        listen(servSocket,0);

		/* accept() extracts the first connection request on the queue of pending connections, 
		creates a new connection socket (conn_sock) with the same properties of servSocket, 
		and allocates a new file descriptor for the socket.  If no pending connections are present on the queue,
		accept() blocks the caller until a connection is present. 
		The connection socket is now used exchage messages with the client. */

        conn_sock=accept(servSocket,NULL,NULL);

        
		/* Once the connection socket is created, it can be read from or written to
		just like a file using the read() and write() system calls. 
		The next read() call simply reads any message available
		on the connection socket and stores it into buf. */

		recvlen = read(conn_sock, buf, BUFSIZE);
		

		
		if (recvlen > 0) {
			buf[recvlen]='\0';
			printf("received number: \"%s\" (%d bytes)\n", buf, recvlen);
		}
		else
			printf("uh oh - something went wrong!\n");
		//process number
		long long n =atoll(buf);
		long long sum=sum_upto(n);
		sprintf(buf, "%lld",sum);

	  /* converts the received message to upper case */
		// for (i=0;i<strlen(buf);i++){
		// 	buf[i]=toupper(buf[i]);
		// }

		/*The capitalized message is written on the connection socket using the write() system call.
		Once written to the connetion socket, the capitalized message is 
		automatically sent to the client since the connection socket
		is already connected to the client. We do not need to specify the client's address here.
		This is an important difference from UDP where for each message has to be sent separately using the address of the client*/

		write(conn_sock,buf,strlen(buf)+1);
	}
    return 0;
}
