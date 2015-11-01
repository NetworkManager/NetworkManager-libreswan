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

nm_libreswan_service_SOURCES = \
	nm-libreswan-service.c \
	nm-libreswan-service.h

nm_libreswan_service_LDADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	-lutil

nm_libreswan_service_helper_SOURCES = \
	nm-libreswan-service-helper.c

nm_libreswan_service_helper_LDADD = \
	$(LIBNM_LIBS) \
	$(LIBNL_LIBS)

install-exec-hook:
	$(LN_S) -f nm-libreswan-service-helper \
		$(DESTDIR)$(libexecdir)/nm-openswan-service-helper

uninstall-hook:
	rm -f $(DESTDIR)$(libexecdir)/nm-openswan-service-helper

noinst_PROGRAMS = show-xfrm

show_xfrm_SOURCES = show-xfrm.c

show_xfrm_LDADD = $(LIBNL_LIBS) $(GLIB_LIBS)

CLEANFILES = *~
