OBJECTS= main.o config.o list.o protocol.o userauth.o \
		libconfig/libconfig.a ../libssh/libssh.a
SHELL = /bin/sh


subdirs = @subdirs@
top_srcdir = ..
srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
bindir = $(exec_prefix)/bin
incldir= $(prefix)/include
infodir = $(prefix)/info
libdir = $(prefix)/lib/
mandir = $(prefix)/man/man1

CC = gcc
CFLAGS = -g -O2 -Wall -I../include/ -Ilibconfig/
LDFLAGS = 
LIBS = -lz -lcrypto  -lpam -lcrypto
INSTALL = /usr/bin/install -c
DYLIB_EXTENSION = so
LIBSSH_LDFLAGS = -shared

all: sftp_server

main.o: server.h libconfig/libconfig.h
list.o: server.h libconfig/libconfig.h
protocol.o: server.h libconfig/libconfig.h
userauth.o: server.h libconfig/libconfig.h
config.o: server.h libconfig/libconfig.h

libconfig/libconfig.a: libconfig/libconfig.h
	make -C libconfig/
../libssh/libssh.a:
	make -C ../libssh/ libssh.a
libconfig/libconfig.h:
	cd libconfig ; ./configure ; cd ..
	make -C libconfig/
sftp_server: $(OBJECTS) 
	make -C ../libssh libssh.a
	$(CC) -o sftp_server $(OBJECTS) $(LIBS) $(LDFLAGS)
install: all
	$(top_srcdir)/mkinstalldirs $(incldir)
	$(top_srcdir)/mkinstalldirs $(libdir)
	$(INSTALL) sftp_server  $(bindir)
clean:
	rm -f *~ sftp_server *.o
distclean: clean
	rm -f Makefile

