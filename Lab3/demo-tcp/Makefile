CC=gcc
CFLAGS = -g 
# uncomment this for SunOS
# LIBS = -lsocket -lnsl

all: tcp-client tcp-serv

tcp-client: tcp-client.o 
	$(CC) -o tcp-client tcp-client.o $(LIBS)

tcp-serv: tcp-serv.o 
	$(CC) -o tcp-serv tcp-serv.o $(LIBS)

tcp-client.o: tcp-client.c

tcp-serv.o: tcp-serv.c

clean:
	rm -f tcp-client tcp-serv tcp-client.o tcp-serv.o 
