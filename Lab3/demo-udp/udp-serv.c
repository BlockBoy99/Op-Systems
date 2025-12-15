/*
        demo-udp-03: udp-recv: a simple udp server
	receive udp messages

        usage:  udp-recv
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>  // required for the socket(), recvfrom(), sendto()
#include <arpa/inet.h>   // required for htons()
#include <ctype.h>

#define BUFSIZE 2048
#define PORTNO 8888

int main(int argc, char **argv)
{
	struct sockaddr_in myaddr;	/* struct variable to store the address of server */
	struct sockaddr_in remaddr;	/* struct variable to store the address of client */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # of bytes received */
	int servSocket;				/* file descriptor for the server socket */
	int msgcnt = 0;			/* count # of messages we received */
	char buf[BUFSIZE];	/* receive buffer to store the received message */
	int i;
    unsigned short port_num=(unsigned short) PORTNO;


	/* create a UDP socket, if not successful, exit with error message.
	The first argument AF_INET of socket() specifies that the socket
	is going to use IPv4 addresses, the next argument SOCK_DGRAM specifies 
	that the type of the socket is UDP, the last argument is for protocol family
	and is set to 0 in most applications. see the man page of socket(). */

	if ((servSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr,"cannot create socket\n");
		exit(1);
	}

	/* Fill up the different fields of the struct variable myaddr with relevant information so
	   that it can be used as a valid address for the server socket */

	myaddr.sin_family = AF_INET;    // this field sets the address type to IPv4
	myaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // this field sets the IP address, we use the IP address of the loopback interface, see the man page of inet_addr()
	myaddr.sin_port = htons(port_num);  // we use port number 2021, see the man page of htons()


	/* bind the socket to the specific IP address and port above. This gives the server
	a specific IP and port number which can be used by clients to
	connect to the server. Note that the socket() call assigns a random port number to the socket
	but we want to use a specific port number at the server, that's why bind() is required on the server side.*/

	if (bind(servSocket, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		printf("Error: bind failed\n");
		return 0;
	}

	/* now loop, receiving data and printing what we received */
	while (1) {
		printf("waiting on port %d\n", port_num);

		/*See the man page of recvfrom() system call. It receives data from the servSocket
		 and writes it into the buf; at most BUFSIZE bytes are read at a time. The number of
		 bytes actually read from servSocket is returned. After this call the struct remaddr
		 is filled in with the source address of the message (in this case it is the client address).
		 The call blocks the server process until some data is received*/

		recvlen = recvfrom(servSocket, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
		
		if (recvlen > 0) {  // print the data if recvlen > 0
			buf[recvlen]='\0';
			printf("received message: \"%s\" (%d bytes)\n", buf, recvlen);
		}
		else
			printf("uh oh - error reading the message!\n");
		

	    /* convert the received message to upper case */
		for (i=0;i<strlen(buf);i++){
			buf[i]=toupper(buf[i]);
		}

		/* see the man page sendto(). It sends data to remaddr. The data is first written from
		buf to the servSocket which then tells the UDP to send the data to the address specified by remaddr.*/
		
		if (sendto(servSocket, buf, strlen(buf), 0, (struct sockaddr *)&remaddr, sizeof(remaddr)) < 0){
			fprintf(stderr, "Error in sendto\n");
			exit(1);
		}
	}
	/* never exits */
}
