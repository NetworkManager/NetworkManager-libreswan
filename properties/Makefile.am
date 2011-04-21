INCLUDES = -I${top_srcdir}

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openswan-properties.la

libnm_openswan_properties_la_SOURCES = \
	nm-openswan.c \
	nm-openswan.h

uidir = $(datadir)/gnome-vpn-properties/openswan
ui_DATA = nm-openswan-dialog.ui

libnm_openswan_properties_la_CPPFLAGS = \
	$(GTK_CFLAGS) \
	$(GCONF_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NM_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

libnm_openswan_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(GCONF_LIBS) \
	$(NM_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(top_builddir)/common-gnome/libnm-openswan-common-gnome.la

libnm_openswan_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = $(ui_DATA)
