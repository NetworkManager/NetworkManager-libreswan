/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-libreswan-service-helper - libreswan integration with NetworkManager
 *
 * Lubomir Rintel <lkundrak@v3.sk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <string.h>

#include "nm-libreswan-helper-service-dbus.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

extern char **environ;

static struct {
	int log_level;
	const char *log_prefix_token;
} gl/*obal*/ = {
	.log_level = LOG_WARNING,
	.log_prefix_token = "???",
};

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
              g_print ("nm-libreswan-helper[%s,%ld]: %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                       gl.log_prefix_token, \
                       (long) getpid (), \
                       nm_utils_syslog_to_str (level) \
                       _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

int
main (int argc, char *argv[])
{
	NMDBusLibreswanHelper *proxy;
	GVariantBuilder environment;
	GError *err = NULL;
	gchar **env;
	gchar **p;
	const char *bus_name = NM_DBUS_SERVICE_LIBRESWAN;
	char *str = NULL;
	char **i_env;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* support old command line arguments. The only reason for that is to
	 * support update of the plugin while being connected. */
	switch (argc) {
	case 1:
		break;
	case 4:
		gl.log_level = _nm_utils_ascii_str_to_int64 (argv[1], 10, 0, LOG_DEBUG, 0);
		gl.log_prefix_token = argv[2];
		bus_name = argv[3];
		break;
	case 3:
		if (strcmp (argv[1], "--bus-name") == 0) {
			bus_name = argv[2];
			break;
		}
		/* fallthrough */
	default:
		g_printerr ("Usage: %s <LEVEL> <PREFIX_TOKEN> <BUS_NAME>\n", argv[0]);
		exit (1);
	}

	if (!g_dbus_is_name (bus_name)) {
		g_printerr ("Not a valid bus name: '%s'\n", bus_name);
		exit (1);
	}

	_LOGD ("command line: %s", (str = g_strjoinv (" ", argv)));
	g_clear_pointer (&str, g_free);

	for (i_env = environ; i_env && *i_env; i_env++)
		_LOGD ("environment: %s", *i_env);

	proxy = nmdbus_libreswan_helper_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                                        bus_name,
	                                                        NM_DBUS_PATH_LIBRESWAN_HELPER,
	                                                        NULL, &err);
	if (!proxy) {
		_LOGW ("Could not create a D-Bus proxy: %s", err->message);
		g_error_free (err);
		exit (1);
	}

	g_variant_builder_init (&environment, G_VARIANT_TYPE ("a{ss}"));
	env = g_listenv ();
	for (p = env; *p; p++) {
		if (strncmp ("PLUTO_", *p, 6))
			continue;
		g_variant_builder_add (&environment, "{ss}", *p, g_getenv (*p));
	}
	g_strfreev (env);

	if (!nmdbus_libreswan_helper_call_callback_sync (proxy,
	                                                 g_variant_builder_end (&environment),
	                                                 NULL, &err)) {
		_LOGW ("Could not call the plugin: %s", err->message);
		g_error_free (err);
		g_object_unref (proxy);
		exit (1);
	}

	g_object_unref (proxy);

	exit (0);
}
