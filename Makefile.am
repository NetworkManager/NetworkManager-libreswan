AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST =

CLEANFILES =

DISTCLEANFILES =

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-more-warnings=yes \
	--with-gtk4

ACLOCAL_AMFLAGS = -I m4

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES =

noinst_LTLIBRARIES =

libexec_PROGRAMS =

noinst_PROGRAMS =

TESTS =

SUBDIRS = po man

###############################################################################

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-libreswan-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-libreswan-service.name

###############################################################################

noinst_LTLIBRARIES += shared/libutils.la

shared_libutils_la_SOURCES = \
	shared/nm-utils/nm-shared-utils.c \
	shared/nm-utils/nm-shared-utils.h \
	shared/utils.c \
	shared/utils.h \
	shared/nm-service-defines.h

shared_libutils_la_CFLAGS = \
	-DPREFIX=\""$(prefix)"\" \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

shared_libutils_la_LIBADD = \
	$(GLIB_LIBS) \
	$(LIBNM_LIBS)

noinst_PROGRAMS += shared/test-utils

TESTS += shared/test-utils

shared_test_utils_SOURCES = shared/test-utils.c

shared_test_utils_CFLAGS = \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

shared_test_utils_LDADD = \
	shared/libutils.la \
	$(LIBNM_LIBS)

###############################################################################

properties/resources.h: properties/gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-header --internal

properties/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir)/properties --generate-dependencies $(srcdir)/properties/gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/properties --generate-source --internal


gtk4/resources.c: properties/gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --generate-dependencies $(srcdir)/properties/gresource.xml |sed "s,^,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 --generate-source --internal

gtk4/%.ui: properties/%.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< |grep -v can-default >$@

# Include a prebuilt file in tarball, to avoid hitting
# https://gitlab.gnome.org/GNOME/gtk/-/merge_requests/4415
EXTRA_DIST += \
	gtk4/nm-libreswan-dialog.ui

editor_sources = \
	properties/nm-libreswan-editor.c \
	properties/nm-libreswan-editor.h

common_CFLAGS = \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-I$(srcdir)/shared \
	$(GLIB_CFLAGS)

###############################################################################

plugin_LTLIBRARIES += properties/libnm-vpn-plugin-libreswan.la

properties_libnm_vpn_plugin_libreswan_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_BASE \
	$(common_CFLAGS) \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_libreswan_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	properties/nm-libreswan-editor-plugin.c \
	properties/nm-libreswan-editor-plugin.h

properties_libnm_vpn_plugin_libreswan_la_LIBADD = \
	shared/libutils.la \
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

nodist_properties_libnm_vpn_plugin_libreswan_editor_la_SOURCES = \
	properties/resources.h \
	properties/resources.c

properties_libnm_vpn_plugin_libreswan_editor_la_SOURCES = \
	$(editor_sources)

properties_libnm_vpn_plugin_libreswan_editor_la_LIBADD = \
	shared/libutils.la \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

properties_libnm_vpn_plugin_libreswan_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-libreswan-editor.ver"

###############################################################################

if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-libreswan-editor.la
endif

properties_libnm_gtk4_vpn_plugin_libreswan_editor_la_CFLAGS = \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_EDITOR \
	$(common_CFLAGS) \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS)

nodist_properties_libnm_gtk4_vpn_plugin_libreswan_editor_la_SOURCES = \
	properties/resources.h \
	gtk4/resources.c

properties_libnm_gtk4_vpn_plugin_libreswan_editor_la_SOURCES = \
	$(editor_sources)

properties_libnm_gtk4_vpn_plugin_libreswan_editor_la_LIBADD = \
	shared/libutils.la \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS)

properties_libnm_gtk4_vpn_plugin_libreswan_editor_la_LDFLAGS = \
	-avoid-version \
	-Wl,--version-script="$(srcdir)/properties/libnm-vpn-plugin-libreswan-editor.ver"

###############################################################################

EXTRA_DIST += \
	properties/libnm-vpn-plugin-libreswan.ver \
	properties/libnm-vpn-plugin-libreswan-editor.ver \
	properties/nm-libreswan-dialog.ui

###############################################################################

if WITH_GNOME
libexec_PROGRAMS += auth-dialog/nm-libreswan-auth-dialog
endif

auth_dialog_nm_libreswan_auth_dialog_CPPFLAGS = \
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

###############################################################################

libexec_PROGRAMS += src/nm-libreswan-service

src_nm_libreswan_service_CPPFLAGS = \
	$(src_cppflags)

src_nm_libreswan_service_LDADD = \
	src/libnm-libreswan-helper-service-dbus.la \
	shared/libutils.la \
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
	shared/libutils.la \
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

BUILT_SOURCES = \
	gtk4/resources.c \
	src/nm-libreswan-helper-service-dbus.h \
	src/nm-libreswan-helper-service-dbus.c \
	properties/resources.c \
	properties/resources.h

CLEANFILES += \
	gtk4/nm-libreswan-dialog.ui \
	gtk4/resources.c \
	src/nm-libreswan-helper-service-dbus.h \
	src/nm-libreswan-helper-service-dbus.c \
	properties/resources.c \
	properties/resources.h

EXTRA_DIST += \
	src/nm-libreswan-helper-service.xml \
	properties/gresource.xml

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

appdatadir = $(datadir)/metainfo
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

