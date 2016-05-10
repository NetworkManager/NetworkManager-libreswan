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

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "nm-libreswan-helper-service-dbus.h"
#include "nm-service-defines.h"

int
main (int argc, char *argv[])
{
	NMDBusLibreswanHelper *proxy;
	GVariantBuilder environment;
	GError *err = NULL;
	gchar **environ;
	gchar **p;
	const char *bus_name;

	switch (argc) {
	case 1:
		bus_name = NM_DBUS_SERVICE_LIBRESWAN;
		break;
	case 3:
		if (strcmp (argv[1], "--bus-name") == 0) {
			bus_name = argv[2];
			break;
		}
		/* fallthrough */
	default:
		g_warning ("Usage: %s [--bus-name <name>]", argv[0]);
		exit (1);
	}

	if (!g_dbus_is_name (bus_name)) {
		g_warning ("Not a valid bus name: '%s'\n", bus_name);
		exit (1);
	}

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	proxy = nmdbus_libreswan_helper_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                                                        bus_name,
	                                                        NM_DBUS_PATH_LIBRESWAN_HELPER,
	                                                        NULL, &err);
	if (!proxy) {
		g_warning ("Could not create a D-Bus proxy: %s", err->message);
		g_error_free (err);
		exit (1);
	}

	g_variant_builder_init (&environment, G_VARIANT_TYPE ("a{ss}"));
	environ = g_listenv ();
	for (p = environ; *p; p++) {
		if (strncmp ("PLUTO_", *p, 6))
			continue;
		g_variant_builder_add (&environment, "{ss}", *p, g_getenv (*p));
	}
	g_strfreev (environ);

	if (!nmdbus_libreswan_helper_call_callback_sync (proxy,
	                                                 g_variant_builder_end (&environment),
	                                                 NULL, &err)) {
		g_warning ("Could not call the plugin: %s", err->message);
		g_error_free (err);
		g_object_unref (proxy);
		exit (1);
	}

	g_object_unref (proxy);

	exit (0);
}
