CC = gcc
LN_S = ln -s
AR = ar
RANLIB = ranlib
CPP = gcc -E
CFLAGS = -Wall -g -O2 -DHAVE_CONFIG_H
CPPFLAGS =  -DHAVE_CONFIG_H
LDFLAGS =  
INSTALL = /usr/bin/install -c
EXEEXT = 
OBJEXT = o
PATH_SEPARATOR = :
SHOBJFLAGS = -fPIC -DPIC
SHOBJLDFLAGS = -shared -rdynamic
SHOBJEXT = so
ARFLAGS = # @ARFLAGS@
AREXT = a
PKGVERS = 0.1.16
PKGVERSMAJOR = `echo $(PKGVERS) | cut -f 1 -d .`

prefix = /usr/local
mandir = ${prefix}/man
sysconfdir = ${prefix}/etc
datadir = ${prefix}/share
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

LIBS = libconfig.$(AREXT) libconfig.$(SHOBJEXT)
BINS =
# The following two lines need to be kept syncronised.
OBJS = libconfig.o conf_space.o conf_section.o conf_apache.o conf_colon.o conf_equal.o conf_xml.o 
SHOBJS = libconfig_shr.o conf_space_shr.o conf_section_shr.o conf_apache_shr.o conf_colon_shr.o conf_equal_shr.o conf_xml_shr.o 

all: $(LIBS) $(BINS)
libconfig.$(SHOBJEXT): $(SHOBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SHOBJFLAGS) $(SHOBJLDFLAGS) -o $@ $^ $(LDFLAGS)

libconfig.$(AREXT): $(OBJS)
	$(AR) rcu $@ $^
	-$(RANLIB) $@

libconfig.o: libconfig.c compat.h win32.h config.h libconfig.h
libconfig_shr.o: libconfig.c compat.h win32.h config.h libconfig.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SHOBJFLAGS) -c -o $@ libconfig.c

%_shr.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SHOBJFLAGS) -c -o $@ $?

libconfig.h: libconfig.h.in
	cat $? | $(CPP) $(CPPFLAGS) - | grep -v '^#' | grep -v '^ *$$' | sed 's/^!/#  /g;s/__BLANK_LINE__//' > $@

test-lc$(EXEEXT): $(LIBS) test-lc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(filter %.c, $^) $(LDFLAGS) -Wl,-R -Wl,. -L. -lconfig

.PHONY: clean distclean install
clean:
	rm -f *.o $(BINS) $(LIBS) libconfig.h *~ test-lc$(EXEEXT) *.dll.a *.dll.def *.dll
distclean: clean
	rm -f Makefile config.h config.status config.log lc_geterrno.3 lc_process.3 lc_cleanup.3 lc_process_file.3 lc_register_var.3 lc_geterrstr.3 lc_register_callback.3 libconfig.3


install: all libconfig.h
	-$(INSTALL) -d $(mandir)
	-$(INSTALL) -d $(mandir)/man3
	-$(INSTALL) -d $(libdir)
	-$(INSTALL) -d $(includedir)
	-$(INSTALL) -m 644 libconfig.$(SHOBJEXT).def $(libdir)/libconfig.$(SHOBJEXT).def
	-$(INSTALL) -m 644 libconfig.$(SHOBJEXT).a $(libdir)/libconfig.$(SHOBJEXT).a
	$(INSTALL) -m 755 libconfig.$(SHOBJEXT) $(libdir)/libconfig.$(SHOBJEXT).$(PKGVERS)
	$(INSTALL) -m 644 libconfig.$(AREXT) $(libdir)/libconfig.$(AREXT)
	$(INSTALL) -m 644 lc_register_callback.3 $(mandir)/man3/lc_register_callback.3
	$(INSTALL) -m 644 lc_register_var.3 $(mandir)/man3/lc_register_var.3
	$(INSTALL) -m 644 lc_process_file.3 $(mandir)/man3/lc_process_file.3
	$(INSTALL) -m 644 lc_geterrstr.3 $(mandir)/man3/lc_geterrstr.3
	$(INSTALL) -m 644 lc_geterrno.3 $(mandir)/man3/lc_geterrno.3
	$(INSTALL) -m 644 lc_process.3 $(mandir)/man3/lc_process.3
	$(INSTALL) -m 644 lc_cleanup.3 $(mandir)/man3/lc_cleanup.3
	$(INSTALL) -m 644 libconfig.3 $(mandir)/man3/libconfig.3
	$(INSTALL) -m 644 libconfig.h $(includedir)/libconfig.h
	-( cd $(libdir) && rm -f libconfig.$(SHOBJEXT).$(PKGVERSMAJOR) && $(LN_S) libconfig.$(SHOBJEXT).$(PKGVERS) libconfig.$(SHOBJEXT).$(PKGVERSMAJOR) )
	-( cd $(libdir) && rm -f libconfig.$(SHOBJEXT) && $(LN_S) libconfig.$(SHOBJEXT).$(PKGVERS) libconfig.$(SHOBJEXT) )
