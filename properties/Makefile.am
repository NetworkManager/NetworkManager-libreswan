plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-libreswan.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-libreswan-properties.la
endif

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/common \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\"

libnm_vpn_plugin_libreswan_la_CFLAGS = \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

libnm_libreswan_properties_la_CFLAGS = \
	-DNM_LIBRESWAN_OLD \
	$(common_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS)

libnm_vpn_plugin_libreswan_la_SOURCES = \
	nm-libreswan.c \
	nm-libreswan.h

libnm_libreswan_properties_la_SOURCES = \
	$(libnm_vpn_plugin_libreswan_la_SOURCES)

libnm_vpn_plugin_libreswan_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(top_builddir)/common/libnm-libreswan-common.la

libnm_libreswan_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(top_builddir)/common/libnm-vpn-plugin-libreswan-common.la

libnm_vpn_plugin_libreswan_la_LDFLAGS = \
        -avoid-version

libnm_libreswan_properties_la_LDFLAGS = \
	$(libnm_vpn_plugin_libreswan_la_LDFLAGS)

uidir = $(datadir)/gnome-vpn-properties/libreswan
ui_DATA = nm-libreswan-dialog.ui

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)
