AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NM_CFLAGS) \
	$(LIBNL_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_OPENSWAN_LOCALEDIR=\"$(datadir)/locale\" \
	-I${top_srcdir}

libexec_PROGRAMS = nm-openswan-service nm-openswan-service-helper

nm_openswan_service_SOURCES = \
	nm-openswan-service.c \
	nm-openswan-service.h

nm_openswan_service_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(NM_LIBS) \
	-lutil

nm_openswan_service_helper_SOURCES = \
	nm-openswan-service-helper.c

nm_openswan_service_helper_LDADD = \
	$(DBUS_LIBS) \
	$(NM_LIBS) \
	$(LIBNL_LIBS)

noinst_PROGRAMS = show-xfrm

show_xfrm_SOURCES = show-xfrm.c

show_xfrm_LDADD = $(LIBNL_LIBS) $(GLIB_LIBS)

CLEANFILES = *~
