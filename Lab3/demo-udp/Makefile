CC=gcc
CFLAGS = -g 
# uncomment this for SunOS
# LIBS = -lsocket -lnsl

all: udp-client udp-serv

udp-client: udp-client.o 
	$(CC) -o udp-client udp-client.o $(LIBS)

udp-serv: udp-serv.o 
	$(CC) -o udp-serv udp-serv.o $(LIBS)

udp-client.o: udp-client.c

udp-serv.o: udp-serv.c

clean:
	rm -f udp-client udp-serv udp-client.o udp-serv.o 
