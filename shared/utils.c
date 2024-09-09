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
                           int ipsec_version,
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
	const char *rightcert;
	const char *leftrsasigkey;
	const char *rightrsasigkey;
	const char *authby;
	const char *local_network;
	const char *remote_network;
	const char *ikev2 = NULL;
	const char *rightid;
	const char *narrowing;
	const char *rekey;
	const char *fragmentation;
	const char *mobike;
	const char *pfs;
	const char *client_family;
	const char *require_id_on_certificate;
	const char *item;
	gboolean is_ikev2 = FALSE;

	g_return_val_if_fail (fd > 0, FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (con_name && *con_name, FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), FALSE);

	is_ikev2 = nm_libreswan_utils_setting_is_ikev2 (s_vpn, &ikev2);

	/* When using IKEv1 (default in our plugin), we should ensure that we make
	 * it explicit to Libreswan (which now defaults to IKEv2): when crypto algorithms
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
		if (!is_ikev2)
			WRITE_CHECK (fd, debug_write_fcn, error, " aggrmode=yes");

		if (   leftid[0] == '%'
		    || leftid[0] == '@'
		    || nm_utils_parse_inaddr_bin (AF_UNSPEC, leftid, NULL)) {
			WRITE_CHECK (fd, debug_write_fcn, error, " leftid=%s", leftid);
		} else
			WRITE_CHECK (fd, debug_write_fcn, error, " leftid=@%s", leftid);
	}

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_HOSTADDRFAMILY);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " hostaddrfamily=%s", item);

	client_family = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_CLIENTADDRFAMILY);
	if (client_family && strlen (client_family))
		WRITE_CHECK (fd, debug_write_fcn, error, " clientaddrfamily=%s", client_family);

	require_id_on_certificate = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE);
	if (require_id_on_certificate && strlen (require_id_on_certificate))
		WRITE_CHECK (fd, debug_write_fcn, error, " require-id-on-certificate=%s", require_id_on_certificate);

	leftrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY);
	rightrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY);
	leftcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT);
	rightcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT);
	authby = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_AUTHBY);
	if (rightcert && strlen (rightcert)) {
		WRITE_CHECK (fd, debug_write_fcn, error, " rightcert=%s", rightcert);
		if (!rightrsasigkey)
			rightrsasigkey = "%cert";
	}
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

	if (authby && strlen (authby)) {
		WRITE_CHECK (fd, debug_write_fcn, error, " authby=%s", authby);
	} else if (   !(leftrsasigkey && strlen (leftrsasigkey))
	           && !(rightrsasigkey && strlen (rightrsasigkey))) {
		WRITE_CHECK (fd, debug_write_fcn, error, " authby=secret");
	}

	left = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFT);
	if (left && strlen (left))
		WRITE_CHECK (fd, debug_write_fcn, error, " left=%s", left);
	else
		WRITE_CHECK (fd, debug_write_fcn, error, " left=%%defaultroute");

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT);
	if (nm_streq0 (item, "no")) {
		WRITE_CHECK (fd, debug_write_fcn, error, " leftmodecfgclient=no");
	} else {
		WRITE_CHECK (fd, debug_write_fcn, error, " leftmodecfgclient=yes");
	}

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


	local_network = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LOCALNETWORK);
	if (local_network) {
		WRITE_CHECK (fd, debug_write_fcn, error, " leftsubnet=%s", local_network);
	}

	remote_network = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REMOTENETWORK);
	if (!remote_network || !strlen (remote_network)) {
		int addr_family = AF_UNSPEC;

		/* Detect the address family of the remote subnet. We use in order:
		 * 1) the "clientaddrfamily" property 2) the local network.
		 */
		if (nm_streq0 (client_family, "ipv4")) {
			addr_family = AF_INET;
		} else if (nm_streq0 (client_family, "ipv6")) {
			addr_family = AF_INET6;
		} else {
			if (   local_network
			    && nm_utils_parse_inaddr_prefix_bin (AF_INET, local_network, NULL, NULL)) {
				addr_family = AF_INET;
			} else if (local_network
			    && nm_utils_parse_inaddr_prefix_bin (AF_INET6, local_network, NULL, NULL)) {
				addr_family = AF_INET6;
			}
		}

		if (addr_family == AF_INET6) {
			WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=::/0");
		} else {
			/* For backwards compatibility, if we can't determine the family
			 * assume it's IPv4. Anyway, in the future we need to stop adding
			 * the option automatically. */
			WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=0.0.0.0/0");
		}
	} else {
		WRITE_CHECK (fd, debug_write_fcn, error, " rightsubnet=%s", remote_network);
	}

	if (!is_ikev2) {
		/* When IKEv1 is in place, we enforce XAUTH: so, use IKE version
		 * also to check if XAUTH conf options should be passed to Libreswan.
		 */
		WRITE_CHECK (fd, debug_write_fcn, error, " leftxauthclient=yes");

		default_username = nm_setting_vpn_get_user_name (s_vpn);
		props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER);
		if (!props_username)
			props_username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTUSERNAME);
		if (props_username && strlen (props_username))
			WRITE_CHECK (fd, debug_write_fcn, error,
			             ipsec_version >= 4 ? " leftusername=%s" : " leftxauthusername=%s",
			             props_username);
		else if (default_username && strlen (default_username))
			WRITE_CHECK (fd, debug_write_fcn, error,
			             ipsec_version >= 4 ? " leftusername=%s" : " leftxauthusername=%s",
			             default_username);

		WRITE_CHECK (fd, debug_write_fcn, error,
		             ipsec_version >= 4 ? " remote-peer-type=cisco" : " remote_peer_type=cisco");
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
	else if (!is_ikev2 && leftid)
		WRITE_CHECK (fd, debug_write_fcn, error, " ike=%s", NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE);

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP);
	if (phase2_alg_str && strlen (phase2_alg_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " phase2alg=%s", phase2_alg_str);
	else if (!is_ikev2 && leftid)
		WRITE_CHECK (fd, debug_write_fcn, error, " phase2alg=%s", NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP);

	pfs = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_PFS);
	if (pfs && !strcmp (pfs, "no"))
		WRITE_CHECK (fd, debug_write_fcn, error, " pfs=no");

	phase1_lifetime_str = nm_setting_vpn_get_data_item (s_vpn,
							    NM_LIBRESWAN_KEY_IKELIFETIME);
	if (phase1_lifetime_str && strlen (phase1_lifetime_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " ikelifetime=%s", phase1_lifetime_str);
	else if (!is_ikev2)
		WRITE_CHECK (fd, debug_write_fcn, error, " ikelifetime=%s", NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME);

	phase2_lifetime_str = nm_setting_vpn_get_data_item (s_vpn,
							    NM_LIBRESWAN_KEY_SALIFETIME);
	if (phase2_lifetime_str && strlen (phase2_lifetime_str))
		WRITE_CHECK (fd, debug_write_fcn, error, " salifetime=%s", phase2_lifetime_str);
	else if (!is_ikev2)
		WRITE_CHECK (fd, debug_write_fcn, error, " salifetime=%s", NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME);

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

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDDELAY);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " dpddelay=%s", item);

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDTIMEOUT);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " dpdtimeout=%s", item);

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDACTION);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " dpdaction=%s", item);

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IPSEC_INTERFACE);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " ipsec-interface=%s", item);

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_TYPE);
	if (item && strlen (item))
		WRITE_CHECK (fd, debug_write_fcn, error, " type=%s", item);

	WRITE_CHECK (fd, debug_write_fcn, error, " nm-configured=yes");

	WRITE_CHECK_NEWLINE (fd, trailing_newline, debug_write_fcn, error, " auto=add");

	return TRUE;
}

static const char *
_find_helper (const char *progname, const char **paths, GError **error)
{
	const char **iter = paths;
	GString *tmp;
	const char *ret = NULL;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	tmp = g_string_sized_new (50);
	for (iter = paths; iter && *iter; iter++) {
		g_string_append_printf (tmp, "%s%s", *iter, progname);
		if (g_file_test (tmp->str, G_FILE_TEST_EXISTS)) {
			ret = g_intern_string (tmp->str);
			break;
		}
		g_string_set_size (tmp, 0);
	}
	g_string_free (tmp, TRUE);

	if (!ret) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "Could not find %s binary",
		             progname);
	}
	return ret;
}

const char *
nm_libreswan_find_helper_bin (const char *progname, GError **error)
{
	static const char *paths[] = {
		PREFIX "/sbin/",
		PREFIX "/bin/",
		"/sbin/",
		"/usr/sbin/",
		"/usr/local/sbin/",
		"/usr/bin/",
		"/usr/local/bin/",
		NULL,
	};

	return _find_helper (progname, paths, error);
}

const char *
nm_libreswan_find_helper_libexec (const char *progname, GError **error)
{
	static const char *paths[] = {
		PREFIX "/libexec/ipsec/",
		PREFIX "/lib/ipsec/",
		"/usr/libexec/ipsec/",
		"/usr/local/libexec/ipsec/",
		"/usr/lib/ipsec/",
		"/usr/local/lib/ipsec/",
		NULL,
	};

	return _find_helper (progname, paths, error);
}

void
nm_libreswan_detect_version (const char *path, gboolean *out_is_openswan, int *out_version, char **out_banner)
{
	const char *argv[] = { path, "--version", NULL };
	char *output = NULL;
	const char* v;

	g_return_if_fail (out_is_openswan);
	g_return_if_fail (out_version);

	*out_is_openswan = FALSE;
	*out_version = -1;

	if (!path)
		return;

	g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL);
	if (!output)
		return;

	/*
	 * Examples:
	 * Linux Openswan 2.4.5 (klips)
	 * Linux Libreswan 3.32 (netkey) on 5.8.11-200.fc32.x86_64+debug
	 * Linux Libreswan U4.2rc1/K(no kernel code presently loaded) on 5.6.15-300.fc32.x86_64
	 */

	v = strcasestr (output, "Openswan");
	if (v) {
		v = v + strlen ("Openswan");
		*out_is_openswan = TRUE;
	}

	if (!v) {
		v = strcasestr (output, "Libreswan");
		if (v)
			v = v + strlen ("Libreswan");
	}

	if (v) {
		while (g_ascii_isspace (*v))
			v++;
		if (*v == 'U')
			v++;
		if (g_ascii_isdigit (*v))
			*out_version = *v - '0';
	}

	if (out_banner)
		*out_banner = output;
	else
		g_free (output);
}
