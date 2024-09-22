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

static gboolean
append_printable_val (GString *str, const char *val, GError **error)
{
	const char *p;

	g_return_val_if_fail (val, FALSE);

	for (p = val; *p != '\0'; p++) {
		/* Printable characters except " and space allowed. */
		if (*p != '"' && !g_ascii_isspace (*p) && g_ascii_isprint (*p))
			continue;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			     _("Invalid character in '%s'"), val);
		return FALSE;
	}

	g_string_append (str, val);
	g_string_append_c (str, '\n');
	return TRUE;
}

static gboolean
append_string_val (GString *str, const char *val, GError **error)
{
	const char *p;

	g_return_val_if_fail (val, FALSE);

	for (p = val; *p != '\0'; p++) {
		/* Printable characters except " allowed. */
		if (*p != '"' && g_ascii_isprint (*p))
			continue;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			     _("Invalid character in '%s'"), val);
		return FALSE;
	}

	g_string_append_printf (str, "\"%s\"\n", val);
	return TRUE;
}

static inline gboolean
append_optional_string_val (GString *str, const char *key, const char *val,
                            GError **error)
{
	if (val == NULL || val[0] == '\0')
		return TRUE;
	g_string_append_c (str, ' ');
	g_string_append (str, key);
	g_string_append_c (str, '=');

	if (!append_string_val (str, val, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "), key);
		return FALSE;
	}

	return TRUE;
}

static inline gboolean
append_optional_printable_val (GString *str, const char *key, const char *val,
                               GError **error)
{
	if (val == NULL || val[0] == '\0')
		return TRUE;

	g_string_append_c (str, ' ');
	g_string_append (str, key);
	g_string_append_c (str, '=');

	if (!append_printable_val (str, val, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "), key);
		return FALSE;
	}

	return TRUE;
}

static inline gboolean
append_optional_printable (GString *str, NMSettingVpn *s_vpn, const char *key,
                           GError **error)
{
	return append_optional_printable_val (str,
	                               key,
	                               nm_setting_vpn_get_data_item (s_vpn, key),
	                               error);
}

char *
nm_libreswan_get_ipsec_conf (int ipsec_version,
                             NMSettingVpn *s_vpn,
                             const char *con_name,
                             const char *leftupdown_script,
                             gboolean openswan,
                             gboolean trailing_newline,
                             GError **error)
{
	nm_auto_free_gstring GString *ipsec_conf = NULL;
	const char *username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;
	const char *phase1_lifetime_str;
	const char *phase2_lifetime_str;
	const char *left;
	const char *right;
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
	const char *rekey;
	const char *pfs;
	const char *client_family;
	const char *item;
	gboolean is_ikev2 = FALSE;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (con_name && *con_name, NULL);

	ipsec_conf = g_string_sized_new (1024);
	g_string_append (ipsec_conf, "conn ");
	if (!append_printable_val (ipsec_conf, con_name, error)) {
		g_prefix_error (error, _("Bad connection name: "));
		return FALSE;
	}

	if (leftupdown_script) {
		g_string_append (ipsec_conf, " auto=add\n");
		g_string_append (ipsec_conf, " nm-configured=yes\n");
		g_string_append (ipsec_conf, " leftupdown=");
		if (!append_string_val (ipsec_conf, leftupdown_script, error))
			g_return_val_if_reached (FALSE);
	}

	/* When using IKEv1 (default in our plugin), we should ensure that we make
	 * it explicit to Libreswan (which now defaults to IKEv2): when crypto algorithms
	 * are not specified ("esp" & "ike") Libreswan will use system-wide crypto
	 * policies based on the IKE version in place.
	 */
	is_ikev2 = nm_libreswan_utils_setting_is_ikev2 (s_vpn, &ikev2);
	if (!ikev2)
		ikev2 = NM_LIBRESWAN_IKEV2_NEVER;
	g_string_append (ipsec_conf, " ikev2=");
	if (!append_printable_val (ipsec_conf, ikev2, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "), "ikev2");
		return FALSE;
	}

	right = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT);
	if (right && right[0] != '\0') {
		g_string_append (ipsec_conf, " right=");
		if (!append_printable_val (ipsec_conf, right, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
					NM_LIBRESWAN_KEY_RIGHT);
			return FALSE;
		}
	} else {
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			     _("'%s' key needs to be present."), NM_LIBRESWAN_KEY_RIGHT);
		return FALSE;
	}

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID);
	if (leftid && leftid[0] != '\0') {
		if (!is_ikev2)
			g_string_append (ipsec_conf, " aggrmode=yes\n");

		if (   leftid[0] == '%'
		    || leftid[0] == '@'
		    || nm_utils_parse_inaddr_bin (AF_UNSPEC, leftid, NULL)) {
			g_string_append (ipsec_conf, " leftid=");
		} else
			g_string_append (ipsec_conf, " leftid=@");
		if (!append_printable_val (ipsec_conf, leftid, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
			                NM_LIBRESWAN_KEY_LEFTID);
			return FALSE;
		}
	}

	if (!append_optional_printable (ipsec_conf, s_vpn,
	                                NM_LIBRESWAN_KEY_HOSTADDRFAMILY, error)) {
		return FALSE;
	}

	client_family = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_CLIENTADDRFAMILY);
	if (client_family && client_family[0] != '\0') {
		g_string_append (ipsec_conf, " clientaddrfamily=");
		if (!append_printable_val (ipsec_conf, client_family, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
			                NM_LIBRESWAN_KEY_CLIENTADDRFAMILY);
			return FALSE;
		}
	}

	leftrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY);
	rightrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY);
	leftcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT);
	rightcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT);
	authby = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_AUTHBY);
	if (rightcert && rightcert[0] != '\0') {
		g_string_append (ipsec_conf, " rightcert=");
		if (!append_string_val (ipsec_conf, rightcert, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
			                NM_LIBRESWAN_KEY_RIGHTCERT);
			return FALSE;
		}
		if (!rightrsasigkey)
			rightrsasigkey = "%cert";
	}
	if (leftcert && leftcert[0] != '\0') {
		g_string_append (ipsec_conf, " leftcert=");
		if (!append_string_val (ipsec_conf, leftcert, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
			                NM_LIBRESWAN_KEY_LEFTCERT);
			return FALSE;
		}
		if (!leftrsasigkey)
			leftrsasigkey = "%cert";
		if (!rightrsasigkey)
			rightrsasigkey = "%cert";
	}
	if (!append_optional_string_val (ipsec_conf, NM_LIBRESWAN_KEY_LEFTRSASIGKEY,
	                                 leftrsasigkey, error)) {
		return FALSE;
	}
	if (!append_optional_string_val (ipsec_conf, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY,
	                                 rightrsasigkey, error)) {
		return FALSE;
	}
	if (authby == NULL || authby[0] == '\0') {
		if (   !(leftrsasigkey && leftrsasigkey[0] != '\0')
		    && !(rightrsasigkey && rightrsasigkey[0] != '\0')) {
			authby = "secret";
		}
	}
	if (!append_optional_printable_val (ipsec_conf, NM_LIBRESWAN_KEY_AUTHBY,
	                                    authby, error)) {
		return FALSE;
	}

	left = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFT);
	if (left == NULL || left[0] == '\0')
		left = "%defaultroute";
	g_string_append (ipsec_conf, " left=");
	if (!append_printable_val (ipsec_conf, left, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "),
		                NM_LIBRESWAN_KEY_LEFT);
		return FALSE;
	}

	item = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT);
	if (nm_streq0 (item, "no")) {
		g_string_append (ipsec_conf, " leftmodecfgclient=no\n");
	} else {
		g_string_append (ipsec_conf, " leftmodecfgclient=yes\n");
	}

	rightid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTID);
	if (rightid && rightid[0] != '\0') {
		if (   rightid[0] == '@'
		    || rightid[0] == '%'
		    || nm_utils_parse_inaddr_bin (AF_UNSPEC, rightid, NULL)) {
			g_string_append (ipsec_conf, " rightid=");
		} else {
			g_string_append (ipsec_conf, " rightid=@");
		}
		if (!append_printable_val (ipsec_conf, rightid, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
			                NM_LIBRESWAN_KEY_RIGHTID);
			return FALSE;
		}
	}

	local_network = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LOCALNETWORK);
	if (local_network) {
		g_string_append (ipsec_conf, " leftsubnet=");
		if (!append_printable_val (ipsec_conf, local_network, error)) {
			g_prefix_error (error, _("Invalid value for '%s': "),
					NM_LIBRESWAN_KEY_LOCALNETWORK);
			return FALSE;
		}
	}

	remote_network = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REMOTENETWORK);
	if (!remote_network || remote_network[0] == '\0') {
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
			remote_network = "::/0";
		} else {
			/* For backwards compatibility, if we can't determine the family
			 * assume it's IPv4. Anyway, in the future we need to stop adding
			 * the option automatically. */
			remote_network = "0.0.0.0/0";
		}
	}
	g_string_append (ipsec_conf, " rightsubnet=");
	if (!append_printable_val (ipsec_conf, remote_network, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "),
				NM_LIBRESWAN_KEY_REMOTENETWORK);
		return FALSE;
	}

	if (!is_ikev2) {
		/* When IKEv1 is in place, we enforce XAUTH: so, use IKE version
		 * also to check if XAUTH conf options should be passed to Libreswan.
		 */
		g_string_append (ipsec_conf, " leftxauthclient=yes\n");

		username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER);
		if (username == NULL || username[0] == '\0')
			username = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTUSERNAME);
		if (username == NULL || username[0] == '\0')
			username = nm_setting_vpn_get_user_name (s_vpn);
		if (username != NULL && username[0] != '\0') {
			g_string_append (ipsec_conf,
			                 ipsec_version >= 4 ?
			                 " leftusername=" :
			                 " leftxauthusername=");
			if (!append_string_val (ipsec_conf, username, error)) {
				g_prefix_error (error, _("Invalid username: "));
				return FALSE;
			}
		}

		g_string_append (ipsec_conf,
		                 ipsec_version >= 4 ?
		                 " remote-peer-type=cisco\n" :
		                 " remote_peer_type=cisco\n");
		g_string_append (ipsec_conf, " rightxauthserver=yes\n");
	}

	/* When the crypto is unspecified, let Libreswan use many sets of crypto
	 * proposals (just leave the property unset). An exception should be made
	 * for IKEv1 connections in aggressive mode: there the DH group in the crypto
	 * phase1 proposal must be just one; moreover no more than 4 proposal may be
	 * specified. So, when IKEv1 aggressive mode ('leftid' specified) is configured
	 * force the best proposal that should be accepted by all obsolete VPN SW/HW
	 * acting as a remote access VPN server.
	 */
	phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE);
	if (phase1_alg_str == NULL || phase1_alg_str[0] == '\0') {
		if (!is_ikev2 && leftid)
			phase1_alg_str = NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE;
	}
	if (!append_optional_string_val (ipsec_conf, NM_LIBRESWAN_KEY_IKE, phase1_alg_str, error))
		return FALSE;

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP);
	if (phase2_alg_str == NULL || phase2_alg_str[0] == '\0') {
		if (!is_ikev2 && leftid)
			phase2_alg_str = NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP;
	}
	if (!append_optional_string_val (ipsec_conf, "phase2alg", phase2_alg_str, error))
		return FALSE;

	pfs = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_PFS);
	if (pfs && !strcmp (pfs, "no"))
		g_string_append (ipsec_conf, " pfs=no\n");

	phase1_lifetime_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IKELIFETIME);
	if (phase1_lifetime_str == NULL || phase1_lifetime_str[0] == '\0') {
		if (!is_ikev2)
			phase1_lifetime_str = NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME;
	}
	if (!append_optional_printable_val (ipsec_conf, NM_LIBRESWAN_KEY_IKELIFETIME,
	                                    phase1_lifetime_str, error)) {
		return FALSE;
	}

	phase2_lifetime_str = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_SALIFETIME);
	if (phase2_lifetime_str == NULL || phase2_lifetime_str[0] == '\0') {
		if (!is_ikev2)
			phase2_lifetime_str = NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME;
	}
	if (!append_optional_printable_val (ipsec_conf, NM_LIBRESWAN_KEY_SALIFETIME,
	                                    phase2_lifetime_str, error)) {
		return FALSE;
	}

	rekey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY);
	if (!rekey || rekey[0] == '\0') {
		g_string_append (ipsec_conf, " keyingtries=1\n");
		rekey = "yes";
	}
	g_string_append (ipsec_conf, " rekey=");
	if (!append_printable_val (ipsec_conf, rekey, error)) {
		g_prefix_error (error, _("Invalid value for '%s': "),
		                NM_LIBRESWAN_KEY_REKEY);
		return FALSE;
	}

	if (!openswan && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR), "Cisco") == 0)
		g_string_append (ipsec_conf, " cisco-unity=yes\n");

	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_NARROWING, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_MOBIKE, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_DPDDELAY, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_DPDTIMEOUT, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_DPDACTION, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_IPSEC_INTERFACE, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_TYPE, error))
		return FALSE;
	if (!append_optional_printable (ipsec_conf, s_vpn, NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE, error))
		return FALSE;

	g_string_append (ipsec_conf, " rightmodecfgserver=yes\n");
	g_string_append (ipsec_conf, " modecfgpull=yes");
	if (trailing_newline)
		g_string_append_c (ipsec_conf, '\n');

	return g_string_free (g_steal_pointer (&ipsec_conf), FALSE);
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
