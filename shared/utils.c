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
 * Copyright (C) 2010 - 2024 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>

enum LibreswanParamFlags {
	PARAM_PRINTABLE	= 0x0001, /* No quotes, line breaks or whitespace. */
	PARAM_STRING	= 0x0002, /* Same as above, except with spaces. */
	PARAM_SYNTHETIC	= 0x0004, /* Not configurable, inferred from other options. */
	PARAM_REQUIRED	= 0x0008, /* Mandatory parameter. */
	PARAM_OLD	= 0x0010, /* Only include for libreswan < 4. */
	PARAM_NEW	= 0x0020, /* Only include for libreswan >= 4. */
	PARAM_IGNORE	= 0x0020, /* Not passed to or from Libreswan. */
};

struct LibreswanParam {
	const char *name;
	void (*add_sanitized) (NMSettingVpn *s_vpn, const char *key, const char *val);
	enum LibreswanParamFlags flags;
};

static void
add (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	/* Check redundant since NM 1.24 */
	if (val == NULL || val[0] == '\0')
		return;
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_ikev2 (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	/*
	 * When using IKEv1 (default in our plugin), we should ensure that
	 * we make it explicit to Libreswan (which now defaults to IKEv2):
	 * when crypto algorithms are not specified ("esp" & "ike")
	 * Libreswan will use system-wide crypto policies based on the IKE
	 * version in place.
	 */
	if (val == NULL || val[0] == '\0')
		val = NM_LIBRESWAN_IKEV2_NEVER;
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_id (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	gs_free char *new = NULL;

	if (val == NULL || val[0] == '\0')
		return;
	if (   val[0] == '@' || val[0] == '%'
	    || nm_utils_parse_inaddr_bin (AF_UNSPEC, val, NULL)) {
		nm_setting_vpn_add_data_item (s_vpn, key, val);
	} else {
		new = g_strdup_printf ("@%s", val);
		nm_setting_vpn_add_data_item (s_vpn, key, new);
	}
}

static void
add_leftrsasigkey (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0') {
		if (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT) == NULL)
			return;
		val = "%cert";
	}
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_rightrsasigkey (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0') {
		if (   nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT) == NULL
		    && nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT) == NULL)
			return;
		val = "%cert";
	}
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_left (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0')
		val = "%defaultroute";
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_leftmodecfgclient (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (g_strcmp0 (val, "no") != 0)
		val = "yes";
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_authby (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (   nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY) != NULL
	    || nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY) != NULL)
		return;
	nm_setting_vpn_add_data_item (s_vpn, key, "secret");
}

static void
add_pfs (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (g_strcmp0 (val, "no") != 0)
		return;
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_rekey (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0') {
		val = "yes";
		/*
		 * keyingtries=1 used to be added when rekey defaulted to "yes",
		 * but not when it was set explicitly. I have no idea why.
		 * Keeping the behavior as is, even though it's criminally ugly.
		 */
		nm_setting_vpn_add_data_item (s_vpn, "keyingtries", "1");
	}
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_keyingtries (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	/* Synthetic only. See above. */
}

static void
add_rightsubnet (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	const char *leftsubnet;
	const char *af;

	if (val == NULL || val[0] == '\0') {
		af = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_CLIENTADDRFAMILY);
		if (g_strcmp0 (af, "ipv6") == 0)
			val = "::/0";
	}
	if (val == NULL || val[0] == '\0') {
		leftsubnet = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LOCALNETWORK);
		if (leftsubnet && nm_utils_parse_inaddr_prefix_bin (AF_INET6, leftsubnet, NULL, NULL))
			val = "::/0";
	}
	if (val == NULL || val[0] == '\0') {
		val = "0.0.0.0/0";
	}
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_yes (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	nm_setting_vpn_add_data_item (s_vpn, key, "yes");
}

static void
add_cisco_unity (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR), "Cisco") != 0)
		return;
	add_yes (s_vpn, key, NULL);
}

static void
add_ike (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	/*
	 * When the crypto is unspecified, let Libreswan use many sets of
	 * crypto proposals (just leave the property unset). An exception
	 * should be made for IKEv1 connections in aggressive mode: there
	 * the DH group in the crypto phase1 proposal must be just one;
	 * moreover no more than 4 proposal may be specified. So, when
	 * IKEv1 aggressive mode ('leftid' specified) is configured force
	 * the best proposal that should be accepted by all obsolete VPN
	 * SW/HW acting as a remote access VPN server.
	 */
	if (val == NULL || val[0] == '\0') {
		if (   nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID)
		    && !nm_libreswan_utils_setting_is_ikev2 (s_vpn))
			val = NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE;
	}
	add (s_vpn, key, val);
}

static void
add_phase2alg (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0')
		val = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP);
	if (val == NULL || val[0] == '\0') {
		if (nm_libreswan_utils_setting_is_ikev2 (s_vpn))
			val = NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP;
	}
	nm_setting_vpn_add_data_item (s_vpn, key, val);
}

static void
add_lifetime (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0') {
		if (!nm_libreswan_utils_setting_is_ikev2 (s_vpn))
			val = "24h";
	}
	add (s_vpn, key, val);
}

static void
add_ikev1 (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (nm_libreswan_utils_setting_is_ikev2 (s_vpn))
		return;
	add (s_vpn, key, val);
}

static void
add_ikev1_yes (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	add_ikev1 (s_vpn, key, "yes");
}

static void
add_remote_peer_type (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	add_ikev1 (s_vpn, key, "cisco");
}

static void
add_aggrmode (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID) == NULL)
		return;
	add_ikev1_yes (s_vpn, key, NULL);
}

static void
add_username (NMSettingVpn *s_vpn, const char *key, const char *val)
{
	if (val == NULL || val[0] == '\0')
		val = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER);
	if (val == NULL || val[0] == '\0')
		val = nm_setting_vpn_get_user_name (s_vpn);
	add_ikev1 (s_vpn, key, val);
}


static const struct LibreswanParam params[] = {
	{ NM_LIBRESWAN_KEY_IKEV2,                      add_ikev2,             PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_RIGHT,                      add,                   PARAM_PRINTABLE | PARAM_REQUIRED },
	{ NM_LIBRESWAN_KEY_LEFTID,                     add_id,                PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_RIGHTID,                    add_id,                PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_LEFTCERT,                   add,                   PARAM_STRING },
	{ NM_LIBRESWAN_KEY_RIGHTCERT,                  add,                   PARAM_STRING },
	{ NM_LIBRESWAN_KEY_RIGHTRSASIGKEY,             add_rightrsasigkey,    PARAM_STRING },
	{ NM_LIBRESWAN_KEY_LEFTRSASIGKEY,              add_leftrsasigkey,     PARAM_STRING },
	{ NM_LIBRESWAN_KEY_LEFT,                       add_left,              PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT,          add_leftmodecfgclient, PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_AUTHBY,                     add_authby,            PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_PFS,                        add_pfs,               PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_IKE,                        add_ike,               PARAM_PRINTABLE },

	{ NM_LIBRESWAN_KEY_IKELIFETIME,                add_lifetime,          PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_SALIFETIME,                 add_lifetime,          PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_HOSTADDRFAMILY,             add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_CLIENTADDRFAMILY,           add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_LOCALNETWORK,               add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_REMOTENETWORK,              add_rightsubnet,       PARAM_PRINTABLE },

	{ NM_LIBRESWAN_KEY_LEFTXAUTHUSER,              add_username,          PARAM_STRING | PARAM_OLD },
	{ NM_LIBRESWAN_KEY_LEFTUSERNAME,               add_username,          PARAM_STRING | PARAM_NEW },

	{ NM_LIBRESWAN_KEY_NARROWING,                  add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_FRAGMENTATION,              add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_MOBIKE,                     add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_DPDDELAY,                   add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_DPDTIMEOUT,                 add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_DPDACTION,                  add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_IPSEC_INTERFACE,            add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_TYPE,                       add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE,  add,                   PARAM_PRINTABLE },

	/* Special. */
	{ NM_LIBRESWAN_KEY_REKEY,                      add_rekey,             PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_ESP,                        add                    },
	{ "phase2alg",                                 add_phase2alg,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ NM_LIBRESWAN_KEY_VENDOR,                     add                    },
	{ "cisco-unity",                               add_cisco_unity,       PARAM_PRINTABLE | PARAM_SYNTHETIC },

	/* Synthetic, not stored. */
	{ "keyingtries",                               add_keyingtries,       PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "aggrmode",                                  add_aggrmode,          PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "leftxauthclient",                           add_ikev1_yes,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "rightxauthserver",                          add_ikev1_yes,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "remote-peer-type",                          add_remote_peer_type,  PARAM_PRINTABLE | PARAM_SYNTHETIC | PARAM_NEW },
	{ "remote_peer_type",                          add_remote_peer_type,  PARAM_PRINTABLE | PARAM_SYNTHETIC | PARAM_OLD },
	{ "rightmodecfgserver",                        add_yes,               PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "modecfgpull",                               add_yes,               PARAM_PRINTABLE | PARAM_SYNTHETIC },

	/* Used internally or just ignored altogether. */
	{ NM_LIBRESWAN_KEY_DOMAIN,                     add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_DHGROUP,                    add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PFSGROUP,                   add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PSK_INPUT_MODES,            add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES, add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PSK_VALUE "-flags",         add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_XAUTH_PASSWORD "-flags",    add,                   PARAM_IGNORE },

	{ NULL  }
};

static gboolean
check_val (const char *val, gboolean allow_spaces, GError **error)
{
	const char *p;

	for (p = val; *p != '\0'; p++) {
		if (*p != '"' && g_ascii_isprint (*p)) {
			if (allow_spaces || !g_ascii_isspace (*p))
				continue;
		}
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			     _("Invalid character in '%s'"), val);
		return FALSE;
	}

	return TRUE;
}

static NMSettingVpn *
sanitize_setting_vpn (NMSettingVpn *s_vpn,
                      GError **error)
{
	gs_unref_object NMSettingVpn *sanitized = NULL;
	int handled_items = 0;
	const char *val;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	sanitized = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (sanitized,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN,
	              NULL);

	for (i = 0; params[i].name != NULL; i++) {
		val = nm_setting_vpn_get_data_item (s_vpn, params[i].name);
		if (val != NULL) {
			handled_items++;
		} else if (params[i].flags & PARAM_REQUIRED) {
			g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("'%s' key needs to be present"),
			             params[i].name);
			return FALSE;
		}

		params[i].add_sanitized (sanitized, params[i].name, val);

		val = nm_setting_vpn_get_data_item (sanitized, params[i].name);
		if (val == NULL)
			continue;
		if (!check_val (val, params[i].flags & PARAM_STRING, error))
			return FALSE;
	}

	if (handled_items != nm_setting_vpn_get_num_data_items (s_vpn)) {
		unsigned int length;
		const char **keys;

		keys = nm_setting_vpn_get_data_keys (s_vpn, &length);
		for (i = 0; i < length; i++) {
			if (   (params[i].flags & PARAM_SYNTHETIC) == 0
			    && nm_setting_vpn_get_data_item (sanitized, keys[i])) {
				continue;
			}

		        g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
		                     _("property '%s' invalid or not supported"),
		                     keys[i]);
			return NULL;
		}
		g_return_val_if_reached (NULL);
	}

	return g_steal_pointer (&sanitized);
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
	gs_unref_object NMSettingVpn *sanitized = NULL;
	nm_auto_free_gstring GString *ipsec_conf = NULL;
	const char *val;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (con_name && *con_name, NULL);

	if (!check_val (con_name, FALSE, error))
		return FALSE;

	sanitized = sanitize_setting_vpn (s_vpn, error);
	if (!sanitized)
		return FALSE;

	ipsec_conf = g_string_sized_new (1024);
	g_string_append_printf (ipsec_conf, "conn %s\n", con_name);

	for (i = 0; params[i].name != NULL; i++) {
		val = nm_setting_vpn_get_data_item (sanitized, params[i].name);
		if (val == NULL)
			continue;

		if (ipsec_version >= 4 && (params[i].flags & PARAM_OLD))
			continue;
		else if (ipsec_version < 4 && (params[i].flags & PARAM_NEW))
			continue;

		if (params[i].flags & PARAM_STRING)
			g_string_append_printf (ipsec_conf, " %s=\"%s\"\n", params[i].name, val);
		else if (params[i].flags & PARAM_PRINTABLE)
			g_string_append_printf (ipsec_conf, " %s=%s\n", params[i].name, val);
	}

	if (leftupdown_script) {
		if (!check_val (leftupdown_script, TRUE, error))
			return FALSE;
		g_string_append_printf (ipsec_conf, " leftupdown=\"%s\"\n", leftupdown_script);
		g_string_append (ipsec_conf, " auto=add\n");
		g_string_append (ipsec_conf, " nm-configured=yes");
		if (trailing_newline)
			g_string_append_c (ipsec_conf, '\n');
	}

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
