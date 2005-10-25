OBJECTS= main.o config.o list.o protocol.o userauth.o acl.o \
		libconfig/libconfig.a ../libssh/libssh.la
SHELL = /bin/sh


subdirs = @subdirs@
top_srcdir = ..
top_builddir = ../
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
LIBS = -lz -lgcrypt  -lpam
INSTALL = /usr/bin/install -c
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBSSH_LDFLAGS = 

all: sftp_server

main.o: server.h libconfig/libconfig.h
list.o: server.h libconfig/libconfig.h
protocol.o: server.h libconfig/libconfig.h
userauth.o: server.h libconfig/libconfig.h
config.o: server.h libconfig/libconfig.h

libconfig/libconfig.a: libconfig/libconfig.h
	make -C libconfig/
../libssh/libssh.la:
	make -C ../libssh/ libssh.la
libconfig/libconfig.h:
	cd libconfig ; ./configure ; cd ..
	make -C libconfig/
sftp_server: $(OBJECTS) 
#	make -C ../libssh libssh.la
	$(LIBTOOL) --mode=link $(CC) -o sftp_server $(OBJECTS) $(LIBS) $(LDFLAGS)
install: all
	$(top_srcdir)/mkinstalldirs $(incldir)
	$(top_srcdir)/mkinstalldirs $(libdir)
	$(LIBTOOL) --mode=install $(INSTALL) sftp_server  $(bindir)
clean:
	$(LIBTOOL) --mode=clean rm -f *~ sftp_server *.o
distclean: clean
	rm -f Makefile

