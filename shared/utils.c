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
#include "nm-utils/nm-shared-utils.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>

gboolean
write_config_option_newline (int fd,
                             gboolean new_line,
                             NMDebugWriteFcn debug_write_fcn,
                             GError **error,
                             const char *format, ...)
{
	gs_free char *string = NULL;
	const char *p;
	va_list args;
	gsize l;
	int errsv;
	gssize w;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	va_end (args);

	if (debug_write_fcn)
		debug_write_fcn (string);

	l = strlen (string);
	if (new_line) {
		gs_free char *s = string;

		string = g_new (char, l + 1 + 1);
		memcpy (string, s, l);
		string[l] = '\n';
		string[l + 1] = '\0';
		l++;
	}

	p = string;
	while (true) {
		w = write (fd, p, l);
		if (w == l)
			return TRUE;
		if (w > 0) {
			g_assert (w < l);
			p += w;
			l -= w;
			continue;
		}
		if (w == 0) {
			errsv = EIO;
			break;
		}
		errsv = errno;
		if (errsv == EINTR)
			continue;
		break;
	}
	g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR,
	             _("Error writing config: %s"), g_strerror (errsv));
	return FALSE;
}

gboolean
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *con_name,
                           const char *leftupdown_script,
                           gboolean openswan,
                           gboolean trailing_newline,
                           NMDebugWriteFcn debug_write_fcn,
                           GError **error)
{
	NMSettingVpn *s_vpn;
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;
	const char *phase1_lifetime_str;
	const char *phase2_lifetime_str;
	const char *left;
	const char *leftid;
	const char *leftcert;
	const char *leftrsasigkey;
	const char *rightrsasigkey;
	const char *remote_network;
	const char *ikev2 = NULL;
	const char *rightid;
	const char *narrowing;
	const char *rekey;
	const char *fragmentation;
	const char *mobike;
	gboolean is_ikev2 = FALSE;
	gboolean xauth_enabled = TRUE;

	g_return_val_if_fail (fd > 0, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (con_name && *con_name, FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), FALSE);

	is_ikev2 = nm_libreswan_utils_setting_is_ikev2 (s_vpn, &ikev2);
	/* When IKEv1 is in place, we enforce XAUTH */
	xauth_enabled = !is_ikev2;
	/* When using IKEv1 (default in our plugin), we should ensure that we make
	 * it explicit to Libreswan (which defaults to IKEv2): when crypto algorithms
	 * are not specified ("esp" & "ike") Libreswan will use system-wide crypto
	 * policies based on the IKE version in place.
	 */
	if (!ikev2)
		ikev2 = NM_LIBRESWAN_IKEV2_NEVER;

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID);

#define WRITE_CHECK_NEWLINE(fd, new_line, debug_write_fcn, error, ...) \
	G_STMT_START { \
		if (!write_config_option_newline ((fd), (new_line), debug_write_fcn, (error), __VA_ARGS__)) \
			return FALSE; \
	} G_STMT_END
#define WRITE_CHECK(fd, debug_write_fcn, error, ...) WRITE_CHECK_NEWLINE (fd, TRUE, debug_write_fcn, error, __VA_ARGS__)

	WRITE_CHECK (fd, debug_write_fcn, error, "conn %s", con_name);
	if (leftid && strlen (leftid)) {
		if (xauth_enabled)
			WRITE_CHECK (fd, debug_write_fcn, error, " aggrmode=yes");

		if (   leftid[0] == '%'
		    || leftid[0] == '@'
		    || nm_utils_parse_inaddr_bin (AF_UNSPEC, leftid, NULL)) {
			WRITE_CHECK (fd, debug_write_fcn, error, " leftid=%s", leftid);
		} else
			WRITE_CHECK (fd, debug_write_fcn, error, " leftid=@%s", leftid);
	}

	leftrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY);
	rightrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY);
	leftcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT);
	if (leftcert && strlen (leftcert)) {
		WRITE_CHECK (fd, debug_write_fcn, error, " leftcert=%s", leftcert);
		if (!leftrsasigkey)
			leftrsasigkey = "%cert";
		if (!rightrsasigkey)
			rightrsasigkey = "%cert";
	}
	if (leftrsasigkey && strlen (leftrsasigkey))
		WRITE_CHECK (fd, debug_write_fcn, error, " leftrsasigkey=%s", leftrsasigkey);
	if (rightrsasigkey && strlen (rightrsasigkey))
		WRITE_CHECK (fd, debug_write_fcn, error, " rightrsasigkey=%s", rightrsasigkey);
	if (   !(leftrsasigkey && strlen (leftrsasigkey))
	    && !(rightrsasigkey && strlen (rightrsasigkey))) {
		WRITE_CHECK (fd, debug_write_fcn, error, " authby=secret");
	}

	left = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFT);
	if (left && strlen (left))
		WRITE_CHECK (fd, debug_write_fcn, error, " left=%s", left);
	else
		WRITE_CHECK (fd, debug_write_fcn, error, " left=%%defaultroute");

	WRITE_CHECK (fd, debug_write_fcn, error, " leftmodecfgclient=yes");
	if (leftupdown_script)
		WRITE_CHECK (fd, debug_write_fcn, error, " leftupdown=%s", leftupdown_script);

	WRITE_CHECK (fd, debug_write_fcn, error, " right=%s", nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT));
	rightid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTID);
	if (rightid && strlen (rightid)) {
		if (   rightid[0] == '@'
		    || rightid[0] == '%'
		    ||  nm_utils_parse_inaddr_bin (AF_UNSPEC, rightid, NULL)) {
			WRITE_CHECK (fd, debug_write_fcn, error, " rightid=%s", rightid);
		} else
			WRITE_CHECK (fd, debug_write_fcn, error, " rightid=@%s", rightid);
	}
	WRITE_CHECK (fd, debug_write_fcn, error, " rightmodecfgserver=yes");
	WRITE_CHECK (fd, debug_write_fcn, error, " modecfgpull=yes");

	remote_network = nm_setting_vpn_get_data_item (s_vpn,
						       NM_LIBRESWAN_KEY_REMOTENETWORK);
	if (!remote_network || !strlen (remote_network))
		WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=0.0.0.0/0");
	else
		WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=%s",
			     remote_network);
	if (xauth_enabled) {
		WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthclient=yes");

		default_username = nm_setting_vpn_get_user_name (s_vpn);
		props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER);
		if (props_username && strlen (props_username))
			WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthusername=%s", props_username);
		else if (default_username && strlen (default_username))
			WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthusername=%s", default_username);

		WRITE_CHECK (fd, debug_write_fcn, error, " remote_peer_type=cisco");
		WRITE_CHECK (fd, debug_write_fcn, error, " rightxauthserver=yes");
	}


	phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE);
	/* When the crypto is unspecified, let Libreswan use many sets of crypto
	 * proposals (just leave the property unset). An exception should be made
	 * for IKEv1 connections in aggressive mode: there the DH group in the crypto
	 * phase1 proposal must be just one; moreover no more than 4 proposal may be
	 * specified. So, when IKEv1 aggressive mode ('leftid' specified) is configured
	 * force the best proposal that should be accepted by all obsolete VPN SW/HW
	 * acting as a remote access VPN server.
	 */
	if (phase1_alg_str && strlen (phase1_alg_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " ike=%s", phase1_alg_str);
	else if (xauth_enabled && leftid)
		WRITE_CHECK (fd, debug_write_fcn, error, " ike=aes256-sha1;modp1536");

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP);
	if (phase2_alg_str && strlen (phase2_alg_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " phase2alg=%s", phase2_alg_str);
	else if (xauth_enabled && leftid)
		WRITE_CHECK (fd, debug_write_fcn, error, " phase2alg=aes256-sha1");

	phase1_lifetime_str = nm_setting_vpn_get_data_item (s_vpn,
							    NM_LIBRESWAN_KEY_IKELIFETIME);
	if (phase1_lifetime_str && strlen (phase1_lifetime_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " ikelifetime=%s", phase1_lifetime_str);
	else if (!is_ikev2)
		WRITE_CHECK (fd, debug_write_fcn, error, " ikelifetime=24h");

	phase2_lifetime_str = nm_setting_vpn_get_data_item (s_vpn,
							    NM_LIBRESWAN_KEY_SALIFETIME);
	if (phase2_lifetime_str && strlen (phase2_lifetime_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " salifetime=%s", phase2_lifetime_str);
	else if (!is_ikev2)
		WRITE_CHECK (fd, debug_write_fcn, error, " salifetime=24h");

	rekey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY);
	if (!rekey || !strlen (rekey)) {
		WRITE_CHECK (fd, debug_write_fcn, error, " rekey=yes");
		WRITE_CHECK (fd, debug_write_fcn, error, " keyingtries=1");
	} else
		WRITE_CHECK (fd, debug_write_fcn, error, " rekey=%s", rekey);

	if (!openswan && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR), "Cisco") == 0)
		WRITE_CHECK (fd, debug_write_fcn, error, " cisco-unity=yes");

	WRITE_CHECK (fd, debug_write_fcn, error, " ikev2=%s", ikev2);

	narrowing = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_NARROWING);
	if (narrowing && strlen (narrowing))
		WRITE_CHECK (fd, debug_write_fcn, error, " narrowing=%s", narrowing);

	fragmentation = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION);
	if (fragmentation && strlen (fragmentation))
		WRITE_CHECK (fd, debug_write_fcn, error, " fragmentation=%s", fragmentation);

	mobike = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_MOBIKE);
	if (mobike && strlen (mobike))
		WRITE_CHECK (fd, debug_write_fcn, error, " mobike=%s", mobike);

	WRITE_CHECK (fd, debug_write_fcn, error, " nm-configured=yes");

	WRITE_CHECK_NEWLINE (fd, trailing_newline, debug_write_fcn, error, " auto=add");

	return TRUE;
}
