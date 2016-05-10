plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-libreswan.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-libreswan-properties.la
endif

plugin_sources = \
    nm-libreswan-editor-plugin.c \
    nm-libreswan-editor-plugin.h

editor_sources = \
    nm-libreswan.c \
    nm-libreswan.h

uidir = $(datadir)/gnome-vpn-properties/libreswan
ui_DATA = nm-libreswan-dialog.ui

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    $(GTK_CFLAGS) \
    -I"$(top_srcdir)/shared/" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_libreswan_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(LIBNM_CFLAGS) \
    $(LIBNMA_CFLAGS)

libnm_vpn_plugin_libreswan_la_SOURCES = \
    $(plugin_sources) \
    $(editor_sources)

libnm_vpn_plugin_libreswan_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_LIBS) \
    $(LIBNMA_LIBS) \
    $(top_builddir)/shared/libnm-vpn-plugin-libreswan-shared.la

libnm_vpn_plugin_libreswan_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-libreswan.ver"

###############################################################################

libnm_libreswan_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_libreswan_properties_la_SOURCES = \
    $(plugin_sources) \
    $(editor_sources)

libnm_libreswan_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS) \
    $(top_builddir)/shared/libnm-libreswan-shared.la

libnm_libreswan_properties_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-libreswan-properties.ver"

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
    libnm-libreswan-properties.ver \
    libnm-vpn-plugin-libreswan.ver \
    nm-libreswan-dialog.ui
