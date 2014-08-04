/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openswan-service-helper - openswan integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 * Avesh Agarwal <avagarwa@redhat.com>
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
 * (C) Copyright 2005 Red Hat, Inc.
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include "nm-openswan-service.h"
#include "nm-utils.h"

/* These are here because nm-dbus-glib-types.h isn't exported */
#define DBUS_TYPE_G_ARRAY_OF_UINT          (dbus_g_type_get_collection ("GArray", G_TYPE_UINT))
#define DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UINT (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_ARRAY_OF_UINT))

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	g_warning ("nm-openswan-service-helper did not receive a valid %s from openswan", reason);

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_OPENSWAN,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetFailure", &err,
				    G_TYPE_STRING, reason,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		g_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);

	exit (1);
}

static void
send_ip4_config (DBusGConnection *connection, GHashTable *config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_OPENSWAN,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetIp4Config", &err,
				    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				    config,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		g_warning ("Could not send IPv4 configuration: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);
}

static GValue *
str_to_gvalue (const char *str, gboolean try_convert)
{
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 num)
{
	GValue *val;

	if (num == 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, num);

	return val;
}

static GValue *
addr_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return uint_to_gvalue (temp_addr.s_addr);
}

static GValue *
addr_list_to_gvalue (const char *str)
{
	GValue *val;
	char **split;
	int i;
	GArray *array;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	array = g_array_sized_new (FALSE, TRUE, sizeof (guint32), g_strv_length (split));
	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_array_append_val (array, addr.s_addr);
		} else {
			g_strfreev (split);
			g_array_free (array, TRUE);
			return NULL;
		}
	}

	g_strfreev (split);

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UINT_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

/*
 * Environment variables passed back from 'openswan':
 *
 * PLUTO_PEER                -- vpn gateway address
 * PLUTO_MY_SOURCEIP         -- address
 * PLUTO_CISCO_DNS_INFO/     -- list of dns serverss
 *    PLUTO_PEER_DNS_INFO
 * PLUTO_CISCO_DOMAIN_INFO/  -- default domain name
 *    PLUTO_PEER_DOMAIN_INFO
 * PLUTO_PEER_BANNER         -- banner from server
 *
 */
int 
main (int argc, char *argv[])
{
	DBusGConnection *connection;
	char *tmp=NULL;
	GHashTable *config;
	GValue *val;
	GError *err = NULL;
	struct in_addr temp_addr;
	char nmask[16]="255.255.255.255";

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* openswan gives us a "reason" code.  If we are given one,
	 * don't proceed unless its "connect".
	 */
	tmp = getenv ("openswan_reason");
	if (!tmp)
		tmp = getenv ("libreswan_reason");
	if (g_strcmp0 (tmp, "connect") != 0)
		exit (0);

	
	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Could not get the system bus: %s", err->message);
		exit (1);
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);


	/* Right peer (or Gateway) */
	val = addr_to_gvalue (getenv ("PLUTO_PEER"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY, val);
	else
		helper_failed (connection, "Openswan Pluto Right Peer (VPN Gateway)");


	/*
	 * Tunnel device
	 * Indicate that openswan plugin doesn't use tun/tap device
	 */
	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE);
	g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);

#if 0
	/* Tunnel device */
	//val = str_to_gvalue (getenv ("TUNDEV"), FALSE);
	//val = str_to_gvalue ("tun0", FALSE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	else
		helper_failed (connection, "Tunnel Device");
#endif

	/* IP address */
	val = addr_to_gvalue (getenv ("PLUTO_MY_SOURCEIP"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (connection, "IP4 Address");

	/* PTP address; for openswan PTP address == internal IP4 address */
	val = addr_to_gvalue (getenv ("PLUTO_MY_SOURCEIP"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (connection, "IP4 PTP Address");

	/* Netmask */
	tmp = nmask;
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		GValue *value;

		value = g_slice_new0 (GValue);
		g_value_init (value, G_TYPE_UINT);
		g_value_set_uint (value, nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));

		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, value);
	}

	/* DNS */
	val = addr_list_to_gvalue (getenv ("PLUTO_CISCO_DNS_INFO"));
	if (!val) {
		/* libreswan value */
		val = addr_list_to_gvalue (getenv ("PLUTO_PEER_DNS_INFO"));
	}
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);


	/* Default domain */
	val = str_to_gvalue (getenv ("PLUTO_CISCO_DOMAIN_INFO"), TRUE);
	if (!val) {
		/* libreswan value */
		val = str_to_gvalue (getenv ("PLUTO_PEER_DOMAIN_INFO"), TRUE);
	}
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* Banner */
	val = str_to_gvalue (getenv ("PLUTO_PEER_BANNER"), TRUE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_BANNER, val);


	/* Send the config info to nm-openswan-service */
	send_ip4_config (connection, config);

	exit (0);
}
