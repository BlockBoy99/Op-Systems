/*
	send udp messages
	This sends a text message entered by a user

        usage:  udp-send
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


int main(void)
{
	struct sockaddr_in remaddr;  // custom struct variable to hold addresses of the server
	int clientSocket;   // int file descriptor to represent client socket
	char buf[BUFLEN];	/* character array to store text messages */
	int len, recvlen;		/* track the lengths of messages */
	unsigned short port_num=PORTNO;


	/* create a UDP socket, if not successful, exit with error message.
	The first argument AF_INET of socket() specifies that the socket
	is going to use IPv4 addresses, the next argument SOCK_DGRAM specifies 
	that the type of the socket is UDP, the last argument is for protocol family
	and is set to 0 in most applications. see the man page of socket(). */
							
	if ((clientSocket=socket(AF_INET, SOCK_DGRAM, 0))<0){
		printf("Error: Socket creation failed\n");
		exit(1);
	}



	/* now define remaddr, the address to whom we want to send messages. 
	For convenience, the host address is expressed as a numeric IP address 
	that we will convert to a binary format via inet_aton */

	remaddr.sin_family = AF_INET;
	remaddr.sin_port = htons(port_num); // this specifies the server port. htons() converts host byte order to network byte order
	remaddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // this specifies the server's IP address

  /*  getting a message from the user */
	printf("Enter a message: ");
	fgets(buf,BUFLEN,stdin);
	len=findlen(buf);
	buf[len]='\0';
	



	/* see the man page sendto(). It sends data to remaddr. The data is first written from
		buf to the clientSocket which then tells the UDP to send the data to the address specified by remaddr.*/

	if (sendto(clientSocket, buf, strlen(buf), 0, (struct sockaddr *)&remaddr, sizeof(remaddr)) < 0) {
		printf("Error: sendto\n");
		exit(1);
	}
	printf("Sent message: %s\n",buf);


		/* now receive a mesage from the server */
	recvlen = recvfrom(clientSocket, buf, BUFLEN, 0, NULL, NULL);
  if (recvlen >= 0) {
          buf[recvlen] = '\0';	/* expect a printable string - terminate it */
          printf("received message: \"%s\"\n", buf);
  }
	close(clientSocket);
	return 0;
}
