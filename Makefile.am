SUBDIRS = libssh include

AM_CPPFLAGS = -I$(srcdir)/include

LDADD = $(top_builddir)/libssh/libssh.la

noinst_PROGRAMS = samplesshd samplessh 

noinst_DATA = samplesftp doxygen

samplessh_SOURCES = sample.c

samplesshd_SOURCES = samplesshd.c

samplesftp: samplessh
	$(LN_S) -f samplessh samplesftp

if HAS_DOXYGEN
install-doc: doxygen
	$(INSTALL) -d $(DESTDIR)$(docdir)/html
	$(INSTALL) --mode=644 doxygen/html/* $(DESTDIR)$(docdir)/html
	$(INSTALL) -d $(DESTDIR)$(docdir)/examples
	$(INSTALL) --mode=644 sample.c samplesshd.c $(DESTDIR)$(docdir)/examples
	$(INSTALL) -d $(DESTDIR)$(mandir)/man3
	$(INSTALL) --mode=644 doxygen/man/man3/* $(DESTDIR)$(mandir)/man3

doxygen: clean-local
	@echo "Running doxygen..."
	doxygen $(srcdir)/Doxyfile
doxygen-dev: clean-local
	@echo "Running internal doxygen"
	doxygen $(srcdir)/Doxyfile.internal
else
doxygen:
doxygen-dev:
install-doc: doxygen
endif

clean-local:
	-rm -rf doxygen

EXTRA_DIST = Doxyfile Doxyfile.internal

CLEANFILES = samplesftp
