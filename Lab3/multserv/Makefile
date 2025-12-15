CC=gcc
CFLAGS = -g 
# uncomment this for SunOS
LIBS = -lpthread

all: tcp-client tcp-serv

tcp-client: tcp-client.c
	$(CC) -o tcp-client tcp-client.c $(LIBS)

tcp-serv: tcp-serv.c  
	$(CC) -o tcp-serv tcp-serv.c $(LIBS) 

clean:
	rm -f tcp-client tcp-serv
