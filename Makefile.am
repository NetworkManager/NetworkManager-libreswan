AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST =

CLEANFILES =

DISTCLEANFILES =

DISTCHECK_CONFIGURE_FLAGS = --enable-more-warnings=yes

ACLOCAL_AMFLAGS = -I m4

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

noinst_LTLIBRARIES =

libexec_PROGRAMS =

noinst_PROGRAMS =

SUBDIRS = po man

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

noinst_LTLIBRARIES += properties/libutils.la

properties_libutils_la_SOURCES = \
	shared/utils.c \
	shared/utils.h \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/nm-service-defines.h

properties_libutils_la_CPPFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-libreswan.la

properties_libnm_vpn_plugin_libreswan_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	-DNM_PLUGIN_DIR=\"$(NM_PLUGIN_DIR)\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_libreswan_la_SOURCES = \
	$(plugin_sources)

properties_libnm_vpn_plugin_libreswan_la_LIBADD = \
	properties/libutils.la \
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

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-libreswan-auth-dialog
endif

auth_dialog_nm_libreswan_auth_dialog_CPPFLAGS = \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBSECRET_CFLAGS)

auth_dialog_nm_libreswan_auth_dialog_SOURCES = \
	auth-dialog/main.c

auth_dialog_nm_libreswan_auth_dialog_LDADD = \
	$(LIBNM_LIBS) \
	$(GTK_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

###############################################################################

src_cppflags = \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_LIBRESWAN_LOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	-I$(builddir)/src \
	-I$(srcdir)/src \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNL_CFLAGS)

noinst_LTLIBRARIES += src/libnm-libreswan-helper-service-dbus.la

nodist_src_libnm_libreswan_helper_service_dbus_la_SOURCES = \
	src/nm-libreswan-helper-service-dbus.c \
	src/nm-libreswan-helper-service-dbus.h

src_libnm_libreswan_helper_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(src_cppflags))

src/nm-libreswan-helper-service-dbus.h: src/nm-libreswan-helper-service.xml
	@$(MKDIR_P) src
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

src/nm-libreswan-helper-service-dbus.c: src/nm-libreswan-helper-service-dbus.h
	@true

noinst_LTLIBRARIES += src/libutils.la

src_libutils_la_SOURCES = \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/utils.c \
	shared/utils.h \
	shared/nm-service-defines.h

src_libutils_la_CPPFLAGS = \
	$(src_cppflags)

src_libutils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

###############################################################################

libexec_PROGRAMS += src/nm-libreswan-service

src_nm_libreswan_service_CPPFLAGS = \
	$(src_cppflags)

src_nm_libreswan_service_LDADD = \
	src/libnm-libreswan-helper-service-dbus.la \
	src/libutils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNL_LIBS) \
	-lutil

$(src_nm_libreswan_service_OBJECTS): src/nm-libreswan-helper-service-dbus.h

###############################################################################

libexec_PROGRAMS += src/nm-libreswan-service-helper

src_nm_libreswan_service_helper_CPPFLAGS = \
	$(src_cppflags)

src_nm_libreswan_service_helper_LDADD = \
	src/libnm-libreswan-helper-service-dbus.la \
	src/libutils.la \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

$(src_nm_libreswan_service_helper_OBJECTS): src/nm-libreswan-helper-service-dbus.h

###############################################################################

noinst_PROGRAMS += src/show-xfrm

src_show_xfrm_CPPFLAGS = \
	$(src_cppflags)

src_show_xfrm_LDADD = \
	$(LIBNL_LIBS) \
	$(GLIB_LIBS)

###############################################################################

CLEANFILES += \
	src/nm-libreswan-helper-service-dbus.h \
	src/nm-libreswan-helper-service-dbus.c

EXTRA_DIST += \
	src/nm-libreswan-helper-service.xml

###############################################################################

EXTRA_DIST += \
	shared/README \
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
	@$(MKDIR_P) $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
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

