AM_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

libexec_PROGRAMS = nm-libreswan-auth-dialog

nm_libreswan_auth_dialog_SOURCES = main.c

nm_libreswan_auth_dialog_LDADD = \
	$(LIBNM_LIBS) \
	$(GTK_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBSECRET_LIBS)

@INTLTOOL_DESKTOP_RULE@
desktopdir = $(datadir)/applications
desktop_in_in_files = nm-libreswan-auth-dialog.desktop.in.in
desktop_in_files = nm-libreswan-auth-dialog.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

EXTRA_DIST = \
	$(desktop_in_in_files)

CLEANFILES = \
	*~ \
	$(desktop_DATA)

DISTCLEANFILES = \
	$(desktop_in_files)
