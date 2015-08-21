AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-openswan-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-openswan-service.name

if WITH_LIBNM_GLIB
nmvpnoldservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnoldservice_DATA = nm-openswan-service.name
endif

nm-openswan-service.name: $(srcdir)/nm-openswan-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    $< >$@

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

EXTRA_DIST = nm-openswan-service.name.in \
             $(dbusservice_DATA)  \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in \
             nm-test-helpers.h

CLEANFILES = $(nmvpnservice_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
