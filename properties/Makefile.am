plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openswan-properties.la

AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(NM_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\" \
	-I${top_srcdir}

libnm_openswan_properties_la_SOURCES = \
	nm-openswan.c \
	nm-openswan.h

libnm_openswan_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(NM_LIBS)

libnm_openswan_properties_la_LDFLAGS = \
        -avoid-version

uidir = $(datadir)/gnome-vpn-properties/openswan
ui_DATA = nm-openswan-dialog.ui

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)
