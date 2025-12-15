/*
	send tcp messages
	This sends a text message entered by a user

        usage:  tcp-send opt:int
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFLEN 2048
#define PORTNO 8888

int findlen(char *str){
	int i=0;
	while (str[i]!='\n'){
		i++;
	}
	return i;
}


int main(int argc, char *argv[])
{
	struct sockaddr_in myaddr, remaddr;  // structs to define the addresses of client and server
	int clientSocket, len;
	char buf[BUFLEN];	/* message buffer */
	int recvlen;		/* # bytes in acknowledgement message */
	unsigned short port_num=PORTNO;

	strcpy(buf, argv[1]);//copy number to buf

	/* create a TCP socket, if not successful, exit with error message.
	The first argument AF_INET of socket() specifies that the socket
	is going to use IPv4 addresses, the next argument SOCK_STREAM specifies 
	that the type of the socket is TCP, the last argument is for protocol family
	and is set to 0 in most applications. see the man page of socket(). */

	if ((clientSocket=socket(AF_INET, SOCK_STREAM, 0))<0){
		printf("Error: socket creation failed\n");
		exit(1);
	}



	

	/* now define remaddr, the address to whom we want to send messages */
	/* For convenience, the host address is expressed as a numeric IP address */
	/* that we will convert to a binary format via inet_aton */

	// memset((char *) &remaddr, 0, sizeof(remaddr));
	remaddr.sin_family = AF_INET;
	remaddr.sin_port = htons(port_num); // this specifies the server port. htons() converts host byte order to network byte order
	remaddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // this specifies the server address


	/* client sends a connection request to the server using connect().
	If accepted by the server, the clientSocket is connected to the connection
	socket on the server side. From that point, any data written to the clientsocket
	will be automatically transmitted to the server. see the man page of connect()r*/

	if(connect(clientSocket,(struct sockaddr *)&remaddr,sizeof(remaddr))<0){
		printf("Error: Could not connect to server\n");
		exit(1);
	}


  /*  getting a message from the user */
	// printf("Enter a message: ");
	// fgets(buf,BUFLEN,stdin);
	// len=findlen(buf);
	// buf[len]='\0';
	
	


	/* Once the connection is established between the client and the server,
	the clientSocket can be read from written to just like a file using
	the read() and write system calls. In the following line, write() is used
	to write message to the clientSoket which is then automatically transmitted
	to the server since the client socket is already connected to the server.
	This is a crucial difference from UDP where each message needs to be sent
	separately using the the address of the server. */

	if (write(clientSocket,buf,strlen(buf)+1) < 0) {
		printf("Error: could not send number");
		exit(1);
	}
	printf("Sent message: %s\n",buf);


		/* now receive a mesage from the server */
	recvlen = read(clientSocket, buf, BUFLEN);
	if (recvlen >= 0) {
			buf[recvlen] = '\0';	/* expect a printable string - terminate it */
			printf("received sum: \"%s\"\n", buf);
	}
	close(clientSocket);
	return 0;
}