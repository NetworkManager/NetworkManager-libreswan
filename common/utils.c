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
#endif

#include "nm-libreswan-service.h"
#include "utils.h"

gboolean debug = FALSE;

void
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *bus_name,
                           gboolean openswan)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *con_name = nm_connection_get_uuid (connection);
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;

	g_assert (fd >= 0);
	g_assert (s_vpn);
	g_assert (con_name);

	write_config_option (fd, "conn %s\n", con_name);
	write_config_option (fd, " aggrmode=yes\n");
	write_config_option (fd, " authby=secret\n");
	write_config_option (fd, " left=%%defaultroute\n");
	write_config_option (fd, " leftid=@%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTID));
	write_config_option (fd, " leftxauthclient=yes\n");
	write_config_option (fd, " leftmodecfgclient=yes\n");

	if (bus_name)
		write_config_option (fd, " leftupdown=\"" NM_LIBRESWAN_HELPER_PATH " --bus-name %s\"\n", bus_name);

	default_username = nm_setting_vpn_get_user_name (s_vpn);
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER);
	if (   default_username && strlen (default_username)
		&& (!props_username || !strlen (props_username)))
		write_config_option (fd, " leftxauthusername=%s\n", default_username);
	else
		write_config_option (fd, " leftxauthusername=%s\n", props_username);

	write_config_option (fd, " right=%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_RIGHT));
	write_config_option (fd, " remote_peer_type=cisco\n");
	write_config_option (fd, " rightxauthserver=yes\n");
	write_config_option (fd, " rightmodecfgserver=yes\n");

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
	if (openswan)
		(void) write (fd, "\n", 1);
	if (debug)
		g_print ("\n");
}
