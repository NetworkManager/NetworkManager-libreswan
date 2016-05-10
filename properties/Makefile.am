plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-libreswan.la
if WITH_GNOME
plugin_LTLIBRARIES += libnm-vpn-plugin-libreswan-editor.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-libreswan-properties.la
endif
endif

plugin_sources = \
    nm-libreswan-editor-plugin.c \
    nm-libreswan-editor-plugin.h

editor_sources = \
    nm-libreswan-editor.c \
    nm-libreswan-editor.h

uidir = $(datadir)/gnome-vpn-properties/libreswan
if WITH_GNOME
ui_DATA = nm-libreswan-dialog.ui
endif

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    -I"$(top_srcdir)/shared/" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\"$(datadir)/locale\"

###############################################################################

libnm_vpn_plugin_libreswan_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
    -DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
    $(common_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_libreswan_la_SOURCES = \
    $(plugin_sources)

libnm_vpn_plugin_libreswan_la_LIBADD = \
    $(LIBNM_LIBS) \
    $(top_builddir)/shared/libnm-vpn-plugin-libreswan-shared.la \
    $(top_builddir)/shared/libnm-vpn-editor-utils-shared.la

libnm_vpn_plugin_libreswan_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-libreswan.ver"

###############################################################################

libnm_vpn_plugin_libreswan_editor_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
    $(LIBNM_CFLAGS) \
    $(LIBNMA_CFLAGS)

libnm_vpn_plugin_libreswan_editor_la_SOURCES = \
    $(editor_sources)

libnm_vpn_plugin_libreswan_editor_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_LIBS) \
    $(LIBNMA_LIBS)

libnm_vpn_plugin_libreswan_editor_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-libreswan-editor.ver"

###############################################################################

libnm_libreswan_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(GTK_CFLAGS) \
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
    libnm-vpn-plugin-libreswan-editor.ver \
    nm-libreswan-dialog.ui
