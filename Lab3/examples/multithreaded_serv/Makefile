CC=gcc
CFLAGS = -g 
# uncomment this for SunOS
LIBS = -lpthread

all: tcp-client tcp-serv tcp-serv-threadpool tcp-serv-single

tcp-serv-single: tcp-serv-single.c 
	$(CC) -o tcp-serv-single tcp-serv-single.c $(LIBS)

tcp-client: tcp-client.o 
	$(CC) -o tcp-client tcp-client.o $(LIBS)

tcp-serv: tcp-serv.o 
	$(CC) -o tcp-serv tcp-serv.o $(LIBS)

tcp-client.o: tcp-client.c

tcp-serv.o: tcp-serv.c

tcp-serv-threadpool: tcp-serv-threadpool.o queue.o 
	$(CC) -o tcp-serv-threadpool tcp-serv-threadpool.o queue.o $(LIBS)

tcp-serv-threadpool.o: tcp-serv-threadpool.c
	$(CC) -c tcp-serv-threadpool.c -o tcp-serv-threadpool.o

queue.o: queue.c
	$(CC) -c queue.c -o queue.o 

clean:
	rm -f tcp-client tcp-serv tcp-client.o tcp-serv.o queue.o tcp-serv-threadpool.o tcp-serv-threadpool
