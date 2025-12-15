#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include "queue.h" 

#define BUFSIZE 2048
#define BACKLOG 500
#define PORTNO 8888

#define POOL_SIZE 8
#define QUEUE_SIZE 100


int queue[QUEUE_SIZE];
int q_front = 0, q_back = 0, q_count = 0;

pthread_mutex_t q_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t q_not_empty = PTHREAD_COND_INITIALIZER;

struct queue *q;

void *worker_main(void *arg){
	int recvlen;
	int conn_sock;
	while(1){
		pthread_mutex_lock(&q_mutex);
		while(isempty(q)){
			pthread_cond_wait(&q_not_empty, &q_mutex);
		}
		conn_sock=dequeue_with_item(q);
		pthread_mutex_unlock(&q_mutex);

		long long limit,sum=0;
		recvlen = read(conn_sock, &limit, sizeof(limit));

		if (recvlen > 0) {
			printf("received number: %lld\n", limit);
		}
		else{
			printf("uh oh - something went wrong!\n");
		}
		for (long long i=1; i<=limit;i++){
			sum+=i;
		}
		write(conn_sock,&sum,sizeof(sum)); 
		printf("Worker %ld sent: %lld\n",pthread_self(),sum);
		close(conn_sock);
	}
	printf("worker Terminating ..\n");
	return NULL;
}
// /*Function to be executed by each thread*/
// void *handle_conn(void *arg){
// 	int recvlen;
// 	int conn_sock=*((int *)arg); // copy the value stored in arg
// 	char buf[BUFSIZE];
// 	long long limit;
// 	long long sum=0,i;


// 	// free the allocated memory
// 	free(arg);

// 	//read from connection socket into buf
// 	recvlen = read(conn_sock, &limit, sizeof(limit));

// 	// print received message		
// 	if (recvlen > 0) {
// 		printf("received number: %lld\n", limit);
// 	}
// 	else{
// 		printf("uh oh - something went wrong!\n");
// 	}

// 	//limit=atoll(buf); // convert received text into a long long number

	
// 	for(i=1;i<=limit;i++){ //compute the sum
// 		sum+=i;
// 	}

// 	// send back sum to the sender by writing to the connection socket
// 	write(conn_sock,&sum,sizeof(sum)); 
	
// 	printf("Sent sum %lld. Now terminating thread.\n",sum);
// 	pthread_exit(NULL);

// }

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

	// create queue
    q = create_queue();

	pthread_t workers[POOL_SIZE];
	for(int i=0;i<POOL_SIZE;i++){
		pthread_create(&workers[i],NULL, worker_main, NULL);
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
	//listen(servSocket,BACKLOG);


	/* listen on the socket */
	if (listen(servSocket, BACKLOG) < 0) {
		perror("listen failed");
		exit(1);
	}



	printf("Server running on port %d with %d worker threads\n",PORTNO, POOL_SIZE);


	

	/* now loop, receiving connections and handing them over to threads for processing */

	while (1) {

		//accept an incoming connection and create a connection socket
		//specific to the accepted connection

        conn_sock=accept(servSocket,(struct sockaddr *)&remaddr, &addrlen);
		if (conn_sock < 0) {
			perror("accept failed");
			continue;
		}

		pthread_mutex_lock(&q_mutex);
		enqueue(q,conn_sock);
		pthread_mutex_unlock(&q_mutex);
		pthread_cond_signal(&q_not_empty);
		/*instead of passing the address of the file descriptor for the connection socket to the thread
		it is better to pass its value so that different threads don't write to this address
		simultaneously. So we malloc some memory and store the connection socket's descriptor there
		and pass the address of this dynamically created block */

		//sock_ptr=(int *)malloc(sizeof(int));
		//*sock_ptr=conn_sock;

		//pass the connection socket file descriptor to the thread handling the connection
		//pthread_create(&tid,NULL,handle_conn,(void *)sock_ptr);
	}
	for(i=0;i<POOL_SIZE;i++){
		pthread_join(workers[i],NULL); //the main thread joins with the workers
	}
    return 0;
}
