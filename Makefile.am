AUTOMAKE_OPTIONS = foreign

EXTRA_DIST =

CLEANFILES =

DISTCLEANFILES =

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

ACLOCAL_AMFLAGS = -I m4

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

SUBDIRS = \
	src \
	po

if WITH_GNOME
SUBDIRS += auth-dialog
endif

###############################################################################

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-libreswan-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-libreswan-service.name

uidir = $(datadir)/gnome-vpn-properties/libreswan
if WITH_GNOME
ui_DATA = properties/nm-libreswan-dialog.ui
endif

###############################################################################

plugin_sources = \
	properties/nm-libreswan-editor-plugin.c \
	properties/nm-libreswan-editor-plugin.h

editor_sources = \
	properties/nm-libreswan-editor.c \
	properties/nm-libreswan-editor.h

common_CFLAGS = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS)

###############################################################################

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-libreswan.la

properties_libnm_vpn_plugin_libreswan_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_libreswan_la_SOURCES = \
	shared/utils.c \
	shared/utils.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	$(plugin_sources)

properties_libnm_vpn_plugin_libreswan_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

properties_libnm_vpn_plugin_libreswan_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-libreswan.ver"

###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-vpn-plugin-libreswan-editor.la
endif

properties_libnm_vpn_plugin_libreswan_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_vpn_plugin_libreswan_editor_la_SOURCES = \
	$(editor_sources)

properties_libnm_vpn_plugin_libreswan_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_libreswan_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-libreswan-editor.ver"

###############################################################################

if WITH_GNOME
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-libreswan-properties.la
endif
endif

properties_libnm_libreswan_properties_la_CFLAGS = \
	-DNM_VPN_OLD \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(common_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS)

properties_libnm_libreswan_properties_la_SOURCES = \
	shared/utils.c \
	shared/utils.h \
	$(plugin_sources) \
	$(editor_sources)

properties_libnm_libreswan_properties_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS)

properties_libnm_libreswan_properties_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-libreswan-properties.ver"

###############################################################################

EXTRA_DIST += \
	properties/libnm-libreswan-properties.ver \
	properties/libnm-vpn-plugin-libreswan.ver \
	properties/libnm-vpn-plugin-libreswan-editor.ver \
	properties/nm-libreswan-dialog.ui

###############################################################################

EXTRA_DIST += \
	shared/README \
	shared/nm-utils/gsystem-local-alloc.h \
	shared/nm-utils/nm-glib.h \
	shared/nm-utils/nm-macros-internal.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/nm-vpn-plugin-macros.h \
	shared/nm-default.h \
	shared/nm-service-defines.h \
	shared/utils.c \
	shared/utils.h \
	$(NULL)

###############################################################################

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|@NM_PLUGIN_DIR@|g' \
	    <$(srcdir)/nm-libreswan-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-libreswan-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-libreswan-service.name
endif

appdatadir = $(datadir)/appdata
appdata_files = $(appdata_in_files:.xml.in=.xml)
if WITH_GNOME
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
endif
appdata_in_files = appdata/network-manager-libreswan.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-libreswan-service.name: $(srcdir)/nm-libreswan-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $< >$@

EXTRA_DIST += \
	nm-libreswan-service.name.in \
	$(dbusservice_DATA)  \
	$(appdata_in_files)  \
	$(appdata_files)      \
	intltool-extract.in  \
	intltool-merge.in    \
	intltool-update.in

CLEANFILES += \
	$(nmvpnservice_DATA) \
	$(appdata_files)

DISTCLEANFILES += \
	intltool-extract \
	intltool-merge \
	intltool-update

