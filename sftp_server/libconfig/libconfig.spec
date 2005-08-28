# RPM Spec file for "libconfig"
Summary: Common configuration file parsing library.
Name: libconfig
Version: 0.1.16
Release: 1
Copyright: MIT
Group: System Environment/Libraries
Source: http://www.rkeene.org/files/oss/libconfig/devel/libconfig-0.1.16.tar.gz
URL: http://www.rkeene.org/oss/libconfig/
Vendor: Keene Enterprises
Packager: Roy Keene <libconfig@rkeene.org>

%description
libconfig is common configuration file parsing library.

%prep
%setup -q

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var || exit 1
make

%install
make install

%files
%defattr(-,root,root)
%doc README
%doc AUTHORS
/usr/lib/libconfig.a
/usr/lib/libconfig.so
/usr/lib/libconfig.so.0.1.16
/usr/lib/libconfig.so.0
/usr/include/libconfig.h
/usr/man/man3/lc_register_callback.3
/usr/man/man3/lc_register_var.3
/usr/man/man3/lc_process_file.3
/usr/man/man3/lc_geterrstr.3
/usr/man/man3/lc_geterrno.3
/usr/man/man3/lc_process.3
/usr/man/man3/lc_cleanup.3
/usr/man/man3/libconfig.3
