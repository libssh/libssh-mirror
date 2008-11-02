lib_LTLIBRARIES = libssh.la

libssh_la_SOURCES = auth1.c auth.c base64.c buffer.c	\
		 channels1.c channels.c client.c connect.c	\
		 crc32.c crypt.c dh.c error.c gcrypt_missing.c	\
		 gzip.c init.c kex.c keyfiles.c	\
		 keys.c messages.c misc.c options.c	\
		 packet.c server.c session.c sftp.c	\
		 sftpserver.c string.c wrapper.c \
		 socket.c log.c match.c

libssh_la_CPPFLAGS = -I$(top_srcdir)/include

libssh_la_LDFLAGS = -version-info $(LIBSSH_CURRENT):$(LIBSSH_REVISION):$(LIBSSH_AGE)
