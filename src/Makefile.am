INCLUDES = -I${top_srcdir} 

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(NM_UTILS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\"

libexec_PROGRAMS = nm-openswan-service nm-openswan-service-helper

nm_openswan_service_SOURCES = \
				nm-openswan-service.c \
				nm-openswan-service.h


nm_openswan_service_LDADD = \
				$(DBUS_LIBS) \
				$(GTHREAD_LIBS) \
				$(NM_UTILS_LIBS)


nm_openswan_service_helper_SOURCES = \
				nm-openswan-service-helper.c


nm_openswan_service_helper_LDADD = \
				$(DBUS_LIBS) \
				$(GTHREAD_LIBS) \
				$(NM_UTILS_LIBS)

CLEANFILES = *~
