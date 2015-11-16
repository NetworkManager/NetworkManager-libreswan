AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNL_CFLAGS) \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_LIBRESWAN_LOCALEDIR=\"$(datadir)/locale\"

libexec_PROGRAMS = nm-libreswan-service nm-libreswan-service-helper

# D-Bus stuff
noinst_LTLIBRARIES = libnm-libreswan-helper-service-dbus.la

nodist_libnm_libreswan_helper_service_dbus_la_SOURCES =		\
	nm-libreswan-helper-service-dbus.c			\
	nm-libreswan-helper-service-dbus.h

libnm_libreswan_helper_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-libreswan-helper-service-dbus.h: $(top_srcdir)/src/nm-libreswan-helper-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

nm-libreswan-helper-service-dbus.c:
	@true

nm_libreswan_service_SOURCES = \
	nm-libreswan-service.c \
	nm-libreswan-service.h

nm_libreswan_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNL_LIBS) \
	libnm-libreswan-helper-service-dbus.la \
	-lutil

nm_libreswan_service_helper_SOURCES = \
	nm-libreswan-service-helper.c

nm_libreswan_service_helper_LDADD = \
	$(LIBNM_LIBS) \
	libnm-libreswan-helper-service-dbus.la

install-exec-hook:
	$(LN_S) -f nm-libreswan-service-helper \
		$(DESTDIR)$(libexecdir)/nm-openswan-service-helper

uninstall-hook:
	rm -f $(DESTDIR)$(libexecdir)/nm-openswan-service-helper

noinst_PROGRAMS = show-xfrm

show_xfrm_SOURCES = show-xfrm.c

show_xfrm_LDADD = $(LIBNL_LIBS) $(GLIB_LIBS)

BUILT_SOURCES = nm-libreswan-helper-service-dbus.h nm-libreswan-helper-service-dbus.c

CLEANFILES = *~ $(BUILT_SOURCES)

EXTRA_DIST = nm-libreswan-helper-service.xml
