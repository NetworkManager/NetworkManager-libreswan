noinst_LTLIBRARIES = libnm-libreswan-common.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-vpn-plugin-libreswan-common.la
endif

libnm_libreswan_common_la_SOURCES = \
	utils.c \
	utils.h

libnm_vpn_plugin_libreswan_common_la_SOURCES = \
	$(libnm_libreswan_common_la_SOURCES)

common_CPPFLAGS = \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I"$(top_srcdir)/shared/"

libnm_libreswan_common_la_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(common_CPPFLAGS)

libnm_vpn_plugin_libreswan_common_la_CPPFLAGS = \
	-DNM_VPN_OLD \
	$(LIBNM_GLIB_CFLAGS) \
	$(common_CPPFLAGS)
