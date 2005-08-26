
OBJECTS= main.o
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
CFLAGS = -g -O2 -Wall -g -I../include/
LDFLAGS = -L../libssh/ -lssh
LIBS = -lz -lcrypto 
INSTALL = /usr/bin/install -c
DYLIB_EXTENSION = so
LIBSSH_LDFLAGS = -shared

all: sftp_server

sftp_server: $(OBJECTS) ../libssh/libssh.$(DYLIB_EXTENSION)
	$(CC) -o sftp_server $(OBJECTS) $(LIBS) $(LDFLAGS)
install: all
	$(top_srcdir)/mkinstalldirs $(incldir)
	$(top_srcdir)/mkinstalldirs $(libdir)
	$(INSTALL) sftp_server  $(bindir)
clean:
	rm -f *~ sftp_server *.o
distclean: clean
	rm -f Makefile

