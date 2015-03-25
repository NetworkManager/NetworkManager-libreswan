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
 * Copyright 2005 - 2014 Red Hat, Inc.
 */

#define _GNU_SOURCE 1

#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <linux/xfrm.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>

#include <nm-vpn-plugin.h>
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

	g_warning ("This helper did not receive a valid %s from the IPSec daemon", reason);

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

/********************************************************************/

/* The various SWANs don't tell helper scripts whether upstream sent
 * specific subnets to be routed over the VPN (eg, CISCO_SPLIT_INC).
 * This is what we need to automatically determine 'never-default' behavior.
 * Instead, we have to inspect the kernel's SAD (Security Assocation Database)
 * for IPSec-secured routes pointing to the VPN gateway.
 */

typedef struct {
	struct in_addr gw4;
	gboolean have_routes4;
} RoutesInfo;

static int
verify_source (struct nl_msg *msg, gpointer user_data)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid || creds->uid || creds->gid) {
		if (creds) {
			g_warning ("netlink: received non-kernel message (pid %d uid %d gid %d)",
			           creds->pid, creds->uid, creds->gid);
		} else
			g_warning ("netlink: received message without credentials");
		return NL_STOP;
	}

	return NL_OK;
}

static struct nl_sock *
setup_socket (void)
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc ();
	g_return_val_if_fail (sk, NULL);

	/* Only ever accept messages from kernel */
	err = nl_socket_modify_cb (sk, NL_CB_MSG_IN, NL_CB_CUSTOM, verify_source, NULL);
	g_assert (!err);

	err = nl_connect (sk, NETLINK_XFRM);
	g_assert (!err);
	err = nl_socket_set_passcred (sk, 1);
	g_assert (!err);

	return sk;
}

static int
parse_reply (struct nl_msg *msg, void *arg)
{
	RoutesInfo *info = arg;
	struct nlmsghdr *n = nlmsg_hdr (msg);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_userpolicy_info *xpinfo = NULL;

	if (info->have_routes4) {
		/* already found some routes */
		return NL_SKIP;
	}

	if (n->nlmsg_type != XFRM_MSG_NEWPOLICY) {
		g_warning ("msg type %d not NEWPOLICY", n->nlmsg_type);
		return NL_SKIP;
	}

	/* Netlink message header is followed by 'struct xfrm_userpolicy_info' and
	 * then the attributes.
	 */

	if (!nlmsg_valid_hdr (n, sizeof (struct xfrm_userpolicy_info))) {
		g_warning ("msg too short");
		return -NLE_MSG_TOOSHORT;
	}

	xpinfo = nlmsg_data (n);
	if (nla_parse (tb, XFRMA_MAX,
	               nlmsg_attrdata (n, sizeof (struct xfrm_userpolicy_info)),
	               nlmsg_attrlen (n, sizeof (struct xfrm_userpolicy_info)),
	               NULL) < 0) {
		g_warning ("failed to parse attributes");
		return NL_SKIP;
	}

	if (tb[XFRMA_TMPL]) {
		int attrlen = nla_len (tb[XFRMA_TMPL]);
		struct xfrm_user_tmpl *list = nla_data (tb[XFRMA_TMPL]);
		int i;

		/* We only look for subnet route associations, eg where
		 * (sel->prefixlen_d > 0), and for those associations, we match
		 * the xfrm_user_tmpl's destination address against the PLUTO_PEER.
		 */
		if (xpinfo->sel.family == AF_INET && xpinfo->sel.prefixlen_d > 0) {
			for (i = 0; i < attrlen / sizeof (struct xfrm_user_tmpl); i++) {
				struct xfrm_user_tmpl *tmpl = &list[i];

				if (   tmpl->family == AF_INET
				    && memcmp (&tmpl->id.daddr, &info->gw4, sizeof (struct in_addr)) == 0) {
					info->have_routes4 = TRUE;
					break;
				}
			}
		}
	}

	return NL_OK;
}

static gboolean
have_sad_routes (const char *gw_addr4)
{
	RoutesInfo info = { { 0 }, FALSE };
	struct nl_sock *sk;
	int err;

	if (inet_pton (AF_INET, gw_addr4, &info.gw4) != 1)
		return FALSE;

	sk = setup_socket ();
	if (!sk)
		return FALSE;

	err = nl_send_simple (sk, XFRM_MSG_GETPOLICY, NLM_F_DUMP, NULL, 0);
	if (err < 0) {
		g_warning ("Error sending: %d %s", err, nl_geterror (err));
		goto done;
	}

	nl_socket_modify_cb (sk, NL_CB_VALID, NL_CB_CUSTOM, parse_reply, &info);

	err = nl_recvmsgs_default (sk);
	if (err < 0) {
		g_warning ("Error parsing: %d %s", err, nl_geterror (err));
		goto done;
	}

done:
	nl_socket_free (sk);
	return info.have_routes4;
}

/********************************************************************/

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
bool_to_gvalue (gboolean b)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_BOOLEAN);
	g_value_set_boolean (val, b);
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
 * Environment variables passed to this helper:
 *
 * PLUTO_PEER                -- vpn gateway address
 * PLUTO_MY_SOURCEIP         -- address
 * PLUTO_CISCO_DNS_INFO/     -- list of dns servers
 *    PLUTO_PEER_DNS_INFO
 * PLUTO_CISCO_DOMAIN_INFO/  -- default domain name
 *    PLUTO_PEER_DOMAIN_INFO
 * PLUTO_PEER_BANNER         -- banner from server
 *
 * NOTE: this helper is currently called explicitly by the ipsec up/down
 * script /usr/libexec/ipsec/_updown.netkey when the configuration contains
 * "nm_configured=yes".  Eventually we want to somehow pass the helper
 * directly to pluto/whack with the --updown option.
 */
int 
main (int argc, char *argv[])
{
	DBusGConnection *connection;
	char *tmp=NULL;
	GHashTable *config;
	GValue *val;
	GError *err = NULL;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* The IPSec service gives us a "reason" code.  If we are given one,
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
		helper_failed (connection, "IPsec/Pluto Right Peer (VPN Gateway)");


	/*
	 * Tunnel device
	 * Indicate that this plugin doesn't use tun/tap device
	 */
	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE);
	g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);

	/* IP address */
	val = addr_to_gvalue (getenv ("PLUTO_MY_SOURCEIP"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else
		helper_failed (connection, "IP4 Address");

	/* PTP address; PTP address == internal IP4 address */
	val = addr_to_gvalue (getenv ("PLUTO_MY_SOURCEIP"));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else
		helper_failed (connection, "IP4 PTP Address");

	/* Netmask */
	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, 32);
	g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);

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

	if (have_sad_routes (getenv ("PLUTO_PEER")))
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, bool_to_gvalue (TRUE));

	/* Send the config info to the VPN plugin */
	send_ip4_config (connection, config);

	exit (0);
}
