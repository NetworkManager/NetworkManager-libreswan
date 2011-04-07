INCLUDES = -I${top_srcdir}

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openswan-properties.la

libnm_openswan_properties_la_SOURCES = \
	nm-openswan.c \
	nm-openswan.h

gladedir = $(datadir)/gnome-vpn-properties/openswan
glade_DATA = nm-openswan-dialog.glade

libnm_openswan_properties_la_CPPFLAGS = \
	$(GLADE_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NM_UTILS_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DGLADEDIR=\""$(gladedir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_openswan_properties_la_LIBADD = \
	$(GLADE_LIBS) \
	$(GTK_LIBS) \
	$(GCONF_LIBS) \
	$(NM_UTILS_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(top_builddir)/common-gnome/libnm-openswan-common-gnome.la

libnm_openswan_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST = $(glade_DATA)
