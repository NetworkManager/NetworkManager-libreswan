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

#include "nm-default.h"

#include "utils.h"

#include <unistd.h>
#include <string.h>

gboolean
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *bus_name,
                           gboolean openswan,
                           NMDebugWriteFcn debug_write_fcn,
                           GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *con_name;
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;
	const char *leftid;

	g_return_val_if_fail (!error || !*error, FALSE);

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

#define WRITE_CHECK_NEWLINE(fd, new_line, debug_write_fcn, error, ...) \
	G_STMT_START { \
		if (!write_config_option_newline ((fd), (new_line), debug_write_fcn, (error), __VA_ARGS__)) \
			return FALSE; \
	} G_STMT_END
#define WRITE_CHECK(fd, debug_write_fcn, error, ...) WRITE_CHECK_NEWLINE (fd, TRUE, debug_write_fcn, error, __VA_ARGS__)

	WRITE_CHECK (fd, debug_write_fcn, error, "conn %s", con_name);
	if (leftid) {
		WRITE_CHECK (fd, debug_write_fcn, error, " aggrmode=yes");
		WRITE_CHECK (fd, debug_write_fcn, error, " leftid=@%s", leftid);
	}
	WRITE_CHECK (fd, debug_write_fcn, error, " authby=secret");
	WRITE_CHECK (fd, debug_write_fcn, error, " left=%%defaultroute");
	WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthclient=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " leftmodecfgclient=yes");

	if (bus_name)
		WRITE_CHECK (fd, debug_write_fcn, error, " leftupdown=\"" NM_LIBRESWAN_HELPER_PATH " --bus-name %s\"", bus_name);

	default_username = nm_setting_vpn_get_user_name (s_vpn);
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER);
	if (props_username && strlen (props_username))
		WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthusername=%s", props_username);
	else if (default_username && strlen (default_username))
		WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthusername=%s", default_username);

	WRITE_CHECK (fd, debug_write_fcn, error, " right=%s", nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_RIGHT));
	WRITE_CHECK (fd, debug_write_fcn, error, " remote_peer_type=cisco");
	WRITE_CHECK (fd, debug_write_fcn, error, " rightxauthserver=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " rightmodecfgserver=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " modecfgpull=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=0.0.0.0/0");

	phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_IKE);
	if (!phase1_alg_str || !strlen (phase1_alg_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " ike=aes-sha1");
	else
		WRITE_CHECK (fd, debug_write_fcn, error, " ike=%s", phase1_alg_str);

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_ESP);
	if (!phase2_alg_str || !strlen (phase2_alg_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " esp=aes-sha1;modp1024");
	else
		WRITE_CHECK (fd, debug_write_fcn, error, " esp=%s", phase2_alg_str);

	WRITE_CHECK (fd, debug_write_fcn, error, " rekey=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " salifetime=24h");
	WRITE_CHECK (fd, debug_write_fcn, error, " ikelifetime=24h");
	WRITE_CHECK (fd, debug_write_fcn, error, " keyingtries=1");
	if (!openswan && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_VENDOR), "Cisco") == 0)
		WRITE_CHECK (fd, debug_write_fcn, error, " cisco-unity=yes");

	/* openswan requires a terminating \n (otherwise it segfaults) while
	 * libreswan fails parsing the configuration if you include the \n.
	 * WTF?
	 */
	WRITE_CHECK_NEWLINE (fd, (openswan || !bus_name), debug_write_fcn, error, " auto=add");

	return TRUE;
}
