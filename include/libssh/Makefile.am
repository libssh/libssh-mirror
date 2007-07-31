libsshdir = $(includedir)/libssh
libssh_HEADERS = crypto.h  libssh.h  priv.h  server.h  sftp.h  ssh1.h  ssh2.h
nodist_libssh_HEADERS = config.h

config.h:
	$(LN_S) $(top_srcdir)/config.h ./config.h

DISTCLEANFILES = config.h
