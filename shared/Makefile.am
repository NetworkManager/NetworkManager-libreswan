noinst_LTLIBRARIES = \
    libnm-vpn-plugin-libreswan-shared.la
if WITH_LIBNM_GLIB
noinst_LTLIBRARIES += libnm-libreswan-shared.la
endif

shared_sources = \
    utils.c \
    utils.h \
    nm-service-defines.h

shared_CPPFLAGS = \
    -DLIBEXECDIR=\""$(libexecdir)"\" \
    -I"$(top_srcdir)/shared/"

###############################################################################

libnm_vpn_plugin_libreswan_shared_la_CPPFLAGS = \
    $(LIBNM_CFLAGS) \
    $(shared_CPPFLAGS)

libnm_vpn_plugin_libreswan_shared_la_SOURCES= \
    $(shared_sources)

libnm_vpn_plugin_libreswan_shared_la_LIBADD = \
    $(LIBNM_LIBS)

###############################################################################

libnm_libreswan_shared_la_SOURCES = \
    $(shared_sources)

libnm_libreswan_shared_la_CPPFLAGS = \
    -DNM_VPN_OLD \
    $(LIBNM_GLIB_CFLAGS) \
    $(shared_CPPFLAGS)

libnm_libreswan_shared_la_LIBADD = \
    $(LIBNM_GLIB_LIBS)

###############################################################################

EXTRA_DIST = \
    nm-service-defines.h
