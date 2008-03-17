all: test_tunnel
CFLAGS=-I../include/ -g -Wall
LDFLAGS=-lssh -L../libssh/.libs

test_tunnel: test_tunnel.o authentication.o connection.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o test_tunnel
