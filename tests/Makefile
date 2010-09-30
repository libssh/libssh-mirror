all: test_socket test_tunnel test_exec test_pcap
CFLAGS=-I../include/ -g -Wall -I../build/
LDFLAGS=-lssh -L../build/src/

test_tunnel: test_tunnel.o authentication.o connection.o
	gcc -o $@ $^ $(LDFLAGS)

test_exec: test_exec.o authentication.o connection.o
	gcc -o $@ $^ $(LDFLAGS)

test_socket: test_socket.o
	gcc -o $@ $^ $(LDFLAGS)


test_pcap: test_pcap.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o test_tunnel
