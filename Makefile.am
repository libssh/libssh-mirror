SUBDIRS = libssh include

AM_CPPFLAGS = -I$(srcdir)/include

LDADD = -lssh -L$(srcdir)/libssh


bin_PROGRAMS = samplesshd samplessh samplesftp

samplessh_SOURCES = sample.c

samplesshd_SOURCES = samplesshd.c

samplesftp: samplessh
	$(LN_S) samplessh samplesftp

nodist_samplesftp_SOURCES = samplesftp.c

EXTRA_DIST = Doxyfile
