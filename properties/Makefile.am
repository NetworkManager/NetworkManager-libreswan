plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openswan-properties.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-openswan-properties-old.la
endif

common_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	-I$(top_srcdir)/src \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_openswan_properties_la_CFLAGS = \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

libnm_openswan_properties_old_la_CFLAGS = \
	-DNM_OPENSWAN_OLD \
	$(common_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS)

libnm_openswan_properties_la_SOURCES = \
	nm-openswan.c \
	nm-openswan.h

libnm_openswan_properties_old_la_SOURCES = \
	$(libnm_openswan_properties_la_SOURCES)

libnm_openswan_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS)

libnm_openswan_properties_old_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS)

libnm_openswan_properties_la_LDFLAGS = \
        -avoid-version

libnm_openswan_properties_old_la_LDFLAGS = \
	$(libnm_openswan_properties_la_LDFLAGS)

uidir = $(datadir)/gnome-vpn-properties/openswan
ui_DATA = nm-openswan-dialog.ui

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)
