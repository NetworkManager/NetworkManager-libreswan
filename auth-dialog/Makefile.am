INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-openswan-auth-dialog

nm_openswan_auth_dialog_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(NM_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_openswan_auth_dialog_SOURCES = \
	main.c \
	vpn-password-dialog.c \
	vpn-password-dialog.h

nm_openswan_auth_dialog_LDADD = \
	$(NM_LIBS) \
	$(GTK_LIBS) \
	$(GNOMEKEYRING_LIBS)

CLEANFILES = *~

