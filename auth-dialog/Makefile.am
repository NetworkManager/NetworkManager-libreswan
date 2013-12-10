INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-openswan-auth-dialog

nm_openswan_auth_dialog_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(NM_CFLAGS) \
	$(GTK_CFLAGS) \
	$(NMGTK_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_openswan_auth_dialog_SOURCES = \
	main.c

nm_openswan_auth_dialog_LDADD = \
	$(NM_LIBS) \
	$(GTK_LIBS) \
	$(NMGTK_LIBS) \
	$(LIBSECRET_LIBS)

@INTLTOOL_DESKTOP_RULE@
desktopdir = $(datadir)/applications
desktop_in_in_files = nm-openswan-auth-dialog.desktop.in.in
desktop_in_files = nm-openswan-auth-dialog.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

EXTRA_DIST = \
	$(desktop_in_in_files)

CLEANFILES = \
	*~ \
	$(desktop_DATA)

DISTCLEANFILES = \
	$(desktop_in_files)
