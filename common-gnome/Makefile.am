noinst_LTLIBRARIES=libnm-openswan-common-gnome.la

libnm_openswan_common_gnome_la_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_openswan_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_openswan_common_gnome_la_LIBADD = \
	$(NM_LIBS) \
	$(GLIB_LIBS) \
	$(GNOMEKEYRING_LIBS)

