/* NetworkManager-libreswan -- Network Manager Libreswan plugin
 *
 * Dan Williams <dcbw@redhat.com>
 * Avesh Agarwal <avagarwa@redhat.com>
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
 * Copyright (C) 2010 - 2015 Red Hat, Inc.
 */

#include <unistd.h>
#include <string.h>
#include <glib.h>
#include <NetworkManager.h>

#ifdef NM_LIBRESWAN_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-connection.h>
#define nm_simple_connection_new nm_connection_new
#endif

#include "nm-service-defines.h"
#include "utils.h"

gboolean debug = FALSE;

NMConnection *
nm_libreswan_config_read (gint fd)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GIOChannel *chan;
	gchar *str;

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN, NULL);

	chan = g_io_channel_unix_new (fd);
	while (g_io_channel_read_line (chan, &str, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
		g_strstrip (str);
		if (g_str_has_prefix (str, "conn "))
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, &str[5], NULL);
		else if (g_str_has_prefix (str, "leftid=@"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTID, &str[8]);
		else if (g_str_has_prefix (str, "leftxauthusername="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER, &str[18]);
		else if (g_str_has_prefix (str, "right="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_RIGHT, &str[6]);
		else if (g_str_has_prefix (str, "ike=") && strcmp (str, "ike=aes-sha1"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_IKE, &str[4]);
		else if (g_str_has_prefix (str, "esp=") && strcmp (str, "esp=aes-sha1;modp1024"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_ESP, &str[4]);
		else if (g_str_has_prefix (str, "cisco-unity=yes"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_VENDOR, "Cisco");
		else if (debug)
			g_print ("Ignored line: '%s'", str);
		g_free (str);
	}
	g_io_channel_unref (chan);

	return connection;
}

void
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *bus_name,
                           gboolean openswan)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *con_name;
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;
	const char *leftid;

	/* We abuse the presence of bus name to decide if we're exporting
	 * the connection or actually configuring Pluto. */
	if (bus_name)
		con_name = nm_connection_get_uuid (connection);
	else
		con_name = nm_connection_get_id (connection);

	g_assert (fd >= 0);
	g_assert (s_vpn);
	g_assert (con_name);

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTID);

	write_config_option (fd, "conn %s\n", con_name);
	if (leftid) {
		write_config_option (fd, " aggrmode=yes\n");
		write_config_option (fd, " leftid=@%s\n", leftid);
	}
	write_config_option (fd, " authby=secret\n");
	write_config_option (fd, " left=%%defaultroute\n");
	write_config_option (fd, " leftxauthclient=yes\n");
	write_config_option (fd, " leftmodecfgclient=yes\n");

	if (bus_name)
		write_config_option (fd, " leftupdown=\"" NM_LIBRESWAN_HELPER_PATH " --bus-name %s\"\n", bus_name);

	default_username = nm_setting_vpn_get_user_name (s_vpn);
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER);
	if (props_username && strlen (props_username))
		write_config_option (fd, " leftxauthusername=%s\n", props_username);
	else if (default_username && strlen (default_username))
		write_config_option (fd, " leftxauthusername=%s\n", default_username);

	write_config_option (fd, " right=%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_RIGHT));
	write_config_option (fd, " remote_peer_type=cisco\n");
	write_config_option (fd, " rightxauthserver=yes\n");
	write_config_option (fd, " rightmodecfgserver=yes\n");
	write_config_option (fd, " modecfgpull=yes\n");
	write_config_option (fd, " rightsubnet=0.0.0.0/0\n");

	phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_IKE);
	if (!phase1_alg_str || !strlen (phase1_alg_str))
		write_config_option (fd, " ike=aes-sha1\n");
	else
		write_config_option (fd, " ike=%s\n", phase1_alg_str);

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_ESP);
	if (!phase2_alg_str || !strlen (phase2_alg_str))
		write_config_option (fd, " esp=aes-sha1;modp1024\n");
	else
		write_config_option (fd, " esp=%s\n", phase2_alg_str);

	write_config_option (fd, " rekey=yes\n");
	write_config_option (fd, " salifetime=24h\n");
	write_config_option (fd, " ikelifetime=24h\n");
	write_config_option (fd, " keyingtries=1\n");
	if (!openswan && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_VENDOR), "Cisco") == 0)
		write_config_option (fd, " cisco-unity=yes\n");
	write_config_option (fd, " auto=add");

	/* openswan requires a terminating \n (otherwise it segfaults) while
	 * libreswan fails parsing the configuration if you include the \n.
	 * WTF?
	 */
	if (openswan || !bus_name)
		(void) write (fd, "\n", 1);
	if (debug)
		g_print ("\n");
}
