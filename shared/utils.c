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
	PARAM_IGNORE	= 0x0040, /* Not passed to or from Libreswan. */
	PARAM_SECRET	= 0x0080, /* For secrets */
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
		leftsubnet = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNET);
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
	if (val == NULL) {
		if (g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR), "Cisco") == 0)
			val = "yes";
	}
	if (g_strcmp0 (val, "yes") == 0) {
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR, "Cisco");
		add (s_vpn, key, val);
	}
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
	const char *leftid;

	if (val == NULL || val[0] == '\0')
		val = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP);
	else
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP, val);
	if (val == NULL || val[0] == '\0') {
		leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID);
		if (!nm_libreswan_utils_setting_is_ikev2 (s_vpn) && leftid && leftid[0] != '\0')
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


/*
 * Order matters! Some setters determine the value from other properties --
 * those other properties need to come first. Look out for calls to
 * nm_setting_vpn_get_data_item() or nm_libreswan_utils_setting_is_ikev2()
 * (which refers to IKEV2) to determine which those are.
 *
 * If you must alter the order the test suite has your back.
 */
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
	{ NM_LIBRESWAN_KEY_LEFTSUBNET,                 add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_RIGHTSUBNET,                add_rightsubnet,       PARAM_PRINTABLE },

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
	{ NM_LIBRESWAN_KEY_LEFTSENDCERT,               add,                   PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_RIGHTCA,                    add,                   PARAM_STRING },

	/* Special. */
	{ NM_LIBRESWAN_KEY_REKEY,                      add_rekey,             PARAM_PRINTABLE },
	{ NM_LIBRESWAN_KEY_ESP,                        add,                   PARAM_PRINTABLE },

	/* Used internally or just ignored altogether. */
	{ NM_LIBRESWAN_KEY_VENDOR,                     add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_DOMAIN,                     add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_DHGROUP,                    add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PFSGROUP,                   add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PSK_INPUT_MODES,            add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES, add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_PSK_VALUE,                  add,                   PARAM_IGNORE | PARAM_SECRET},
	{ NM_LIBRESWAN_KEY_PSK_VALUE "-flags",         add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_XAUTH_PASSWORD,             add,                   PARAM_IGNORE | PARAM_SECRET},
	{ NM_LIBRESWAN_KEY_XAUTH_PASSWORD "-flags",    add,                   PARAM_IGNORE },
	{ NM_LIBRESWAN_KEY_NM_AUTO_DEFAULTS,           add,                   PARAM_IGNORE },

	/* Synthetic, not stored. */
	{ "cisco-unity",                               add_cisco_unity,       PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "phase2alg",                                 add_phase2alg,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "keyingtries",                               add_keyingtries,       PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "aggrmode",                                  add_aggrmode,          PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "leftxauthclient",                           add_ikev1_yes,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "rightxauthserver",                          add_ikev1_yes,         PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "remote-peer-type",                          add_remote_peer_type,  PARAM_PRINTABLE | PARAM_SYNTHETIC | PARAM_NEW },
	{ "remote_peer_type",                          add_remote_peer_type,  PARAM_PRINTABLE | PARAM_SYNTHETIC | PARAM_OLD },
	{ "rightmodecfgserver",                        add_yes,               PARAM_PRINTABLE | PARAM_SYNTHETIC },
	{ "modecfgpull",                               add_yes,               PARAM_PRINTABLE | PARAM_SYNTHETIC },

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

NMSettingVpn *
sanitize_setting_vpn (NMSettingVpn *s_vpn,
                      GError **error)
{
	gs_unref_object NMSettingVpn *sanitized = NULL;
	gboolean auto_defaults = TRUE;
	int handled_items = 0;
	const char *val;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	sanitized = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (sanitized,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN,
	              NULL);

	auto_defaults = _nm_utils_ascii_str_to_bool (
		nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_NM_AUTO_DEFAULTS),
		TRUE);

	for (i = 0; params[i].name != NULL; i++) {
		if (params[i].flags & PARAM_SECRET)  {
			val = nm_setting_vpn_get_secret(s_vpn, params[i].name);
			if (val != NULL) {
				nm_setting_vpn_add_secret(sanitized,
							  params[i].name,
							  val);
			}
		} else {
			val = nm_setting_vpn_get_data_item (s_vpn,
							    params[i].name);
			if (val != NULL) {
				handled_items++;
			} else if (params[i].flags & PARAM_REQUIRED) {
				g_set_error (error,
					     NM_UTILS_ERROR,
					     NM_UTILS_ERROR_INVALID_ARGUMENT,
					     _("'%s' key needs to be present"),
					     params[i].name);
				return NULL;
			}

			if (auto_defaults) {
				params[i].add_sanitized (sanitized,
							 params[i].name, val);
			} else {
				nm_setting_vpn_add_data_item (sanitized,
							      params[i].name,
							      val);
			}
		}

		val = nm_setting_vpn_get_data_item (sanitized, params[i].name);
		if (val == NULL)
			continue;
		if (!check_val (val, params[i].flags & PARAM_STRING, error))
			return NULL;
	}

	if (handled_items != nm_setting_vpn_get_num_data_items (s_vpn)) {
		unsigned int length;
		const char **keys;

		keys = nm_setting_vpn_get_data_keys (s_vpn, &length);
		for (i = 0; i < length; i++) {
			if (nm_setting_vpn_get_data_item (sanitized, keys[i]))
				continue;

			g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("property '%s' invalid or not supported"),
			             keys[i]);
			g_free (keys);
			return NULL;
		}
		g_free (keys);
		g_return_val_if_reached (NULL);
	}

	return g_steal_pointer (&sanitized);
}

NMSettingVpn *
get_setting_vpn_sanitized (NMConnection *connection, GError **error)
{
	NMSettingVpn *s_vpn;
	gs_unref_object NMSettingVpn *s_vpn_sanitized = NULL;
	gs_free_error GError *local = NULL;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             _("Invalid VPN setting: %s"), _("Empty VPN configuration"));
		return NULL;
	}

	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &local);
	if (!s_vpn_sanitized) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             _("Invalid VPN setting: %s"), local->message);
		return NULL;
	}

	return g_steal_pointer (&s_vpn_sanitized);
}

char *
nm_libreswan_get_ipsec_conf (int ipsec_version,
                             NMSettingVpn *s_vpn_sanitized,
                             const char *con_name,
                             const char *leftupdown_script,
                             gboolean openswan,
                             gboolean trailing_newline,
                             GError **error)
{
	nm_auto_free_gstring GString *ipsec_conf = NULL;
	gboolean auto_defaults;
	const char *val;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn_sanitized), NULL);
	g_return_val_if_fail (!error || !*error, NULL);
	g_return_val_if_fail (con_name && *con_name, NULL);

	if (!check_val (con_name, FALSE, error))
		return NULL;

	ipsec_conf = g_string_sized_new (1024);

	auto_defaults = _nm_utils_ascii_str_to_bool (
		nm_setting_vpn_get_data_item (s_vpn_sanitized, NM_LIBRESWAN_KEY_NM_AUTO_DEFAULTS),
		TRUE);
	if (!auto_defaults) {
		g_string_append(ipsec_conf, "# NetworkManager specific configs, don't remove:\n");
		g_string_append(ipsec_conf, "# nm-auto-defaults=no\n");
		g_string_append(ipsec_conf, "\n");
	}

	g_string_append_printf (ipsec_conf, "conn %s\n", con_name);

	for (i = 0; params[i].name != NULL; i++) {
		val = nm_setting_vpn_get_data_item (s_vpn_sanitized,
						    params[i].name);
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
			return NULL;
		g_string_append_printf (ipsec_conf, " leftupdown=\"%s\"\n", leftupdown_script);
		g_string_append (ipsec_conf, " auto=add\n");
		g_string_append (ipsec_conf, " nm-configured=yes");
		if (trailing_newline)
			g_string_append_c (ipsec_conf, '\n');
	}

	return g_string_free (g_steal_pointer (&ipsec_conf), FALSE);
}

gboolean
nm_libreswan_check_value (const char *key,
                          const char *val,
                          GError **error)
{
	int i;

	for (i = 0; params[i].name != NULL; i++) {
		if (strcmp (params[i].name, key) != 0)
			continue;

		if (val != NULL && *val != '\0')
			return check_val (val, params[i].flags & PARAM_STRING, error);

		if (params[i].flags & PARAM_REQUIRED) {
			g_set_error (error,
			             NM_UTILS_ERROR,
			             NM_UTILS_ERROR_INVALID_ARGUMENT,
			             _("'%s' key needs to be present"),
			             key);
			return FALSE;
		}
	}

	g_set_error (error,
		     NM_UTILS_ERROR,
		     NM_UTILS_ERROR_INVALID_ARGUMENT,
	             _("property '%s' invalid or not supported"),
		     key);
	return FALSE;

}

/*
 * The format as described in ipsec.conf(5) is fairly primitive.
 * In values, no line breaks are allowed. If there's other whitespace,
 * it needs to be enclosed in quote marks. Quote marks are not allowed
 * elsewhere. There's no escaping of the quote marks or newlines or
 * anything else. This makes it feasible to parse it with a fairly
 * regexp.
 */
static const char line_match[] =
	"^(?:"
	    "(?:conn\\s+|\\s+(\\S+)\\s*=\\s*)"	/* <"conn "> or <whitespace><key>...=... */
	    "(?:\"([^\"]*)\"|(\\S+))"		/* <value> or "<v a l u e>" */
	")?"					/* (or just blank line) */
	"\\s*(?:#.*)?$";			/* optional comment */

static const char no_auto_match[] = "#\\s*nm-auto-defaults\\s*=\\s*no";

NMSettingVpn *
nm_libreswan_parse_ipsec_conf (const char *ipsec_conf,
                               char **out_con_name,
                               GError **error)
{
	gs_unref_object NMSettingVpn *sanitized = NULL;
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	gs_strfreev char **lines = NULL;
	gs_free char *con_name = NULL;
	GMatchInfo *match_info = NULL;
	GError *parse_error = NULL;
	gboolean has_no_auto_defaults = FALSE;
	g_autoptr(GRegex) line_regex = NULL;
	g_autoptr(GRegex) no_auto_regex = NULL;
	const char *old, *new;
	const char *rekey;
	char *key, *val;
	int i;

	g_return_val_if_fail (ipsec_conf, NULL);
	g_return_val_if_fail (out_con_name && !*out_con_name, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	line_regex = g_regex_new (line_match, G_REGEX_RAW, 0, NULL);
	g_return_val_if_fail (line_regex, NULL);
	no_auto_regex = g_regex_new (no_auto_match, G_REGEX_RAW, 0, NULL);
	g_return_val_if_fail (no_auto_regex, NULL);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	lines = g_strsplit_set (ipsec_conf, "\r\n", -1);
	for (i = 0; lines[i]; i++) {
		if (!g_regex_match (line_regex, lines[i], 0, &match_info)) {
			parse_error = g_error_new (
				NM_UTILS_ERROR,
				NM_UTILS_ERROR_INVALID_ARGUMENT,
				_("'%s' not understood"),
				lines[i]);
			g_match_info_unref (match_info);
			break;
		}

		if (g_regex_match(no_auto_regex, lines[i], 0, NULL)) {
			has_no_auto_defaults = TRUE;
			continue;
		}

		key = g_match_info_fetch (match_info, 1); /* Key */
		val = g_match_info_fetch (match_info, 2); /* Unquoted value */
		/* Without fix from
		 * https://gitlab.gnome.org/GNOME/glib/-/commit/b052620398237ce7
		 * key and value might be NULL for empty line or comment only
		 * line.
		 */
		if (val && val[0] == '\0') {
			g_free (val);
			/* Quoted value (quotes stripped off) */
			val = g_match_info_fetch (match_info, 3);
		}
		g_match_info_unref (match_info);

		if (key && key[0] != '\0') {
			/* key=value line */
			if (con_name == NULL) {
				parse_error = g_error_new (
					NM_UTILS_ERROR,
					NM_UTILS_ERROR_INVALID_ARGUMENT,
					_("Expected a conn line before '%s'"),
					key);
			} else if (nm_setting_vpn_get_data_item (s_vpn, key)) {
				parse_error = g_error_new (
					NM_UTILS_ERROR,
					NM_UTILS_ERROR_INVALID_ARGUMENT,
					_("'%s' specified multiple times"),
					key);
			} else {
				nm_setting_vpn_add_data_item (s_vpn, key, val);
			}
			g_free (key);
			g_free (val);
		} else if (val && val[0] != '\0') {
			/* If key didn't match, then this must be a "conn" line. */
			g_free (key);
			if (con_name != NULL) {
				g_free (val);
				parse_error = g_error_new (
					NM_UTILS_ERROR,
					NM_UTILS_ERROR_INVALID_ARGUMENT,
					_("'%s' specified multiple times"),
					"conn");
			} else {
				con_name = val;
			}
		} else {
			/* Blank line */
			g_free (key);
			g_free (val);
		}

		if (parse_error)
			break;
	}

	if (parse_error) {
		g_propagate_error (error, parse_error);
		return NULL;
	}

	/* The "keyingtries" kludge. See above. */
	rekey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY);
	if (  rekey && rekey[0] != '\0'
	    && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, "keyingtries"), "1") == 0) {
		nm_setting_vpn_remove_data_item (s_vpn, "keyingtries");
	}

	/* Params with the PARAM_IGNORE flags are internal only, they shouldn't be
	 * defined in the input file. Reject them here. Any other unknown param will
	 * be rejected by sanitize_setting_vpn(), but it cannot reject these
	 * because they are valid internally. */
	for (i = 0; params[i].name != NULL; i++) {
		if ((params[i].flags & PARAM_IGNORE) != 0) {
			if (nm_setting_vpn_get_data_item (s_vpn, params[i].name)) {
				g_set_error (error,
				             NM_UTILS_ERROR,
				             NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("property '%s' invalid or not supported"),
				             params[i].name);
				return NULL;
			}
		}
	}

	if (has_no_auto_defaults)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_NM_AUTO_DEFAULTS, "no");

	sanitized = sanitize_setting_vpn (s_vpn, error);
	if (!sanitized)
		return NULL;

	g_return_val_if_fail (con_name, NULL);

	/*
	 * Verify that the synthetic properties are either not present in the
	 * original connection, or have the same value as has been synthesized,
	 * Then remove them.
	 */
	for (i = 0; params[i].name != NULL; i++) {
		if ((params[i].flags & PARAM_SYNTHETIC) == 0)
			continue;

		old = nm_setting_vpn_get_data_item (s_vpn, params[i].name);
		if (old != NULL) {
			new = nm_setting_vpn_get_data_item (sanitized, params[i].name);
			if (g_strcmp0 (old, new) != 0) {
				g_set_error (error,
				             NM_UTILS_ERROR,
				             NM_UTILS_ERROR_INVALID_ARGUMENT,
				             _("'%s' is not supported for '%s'"),
				             old, params[i].name);
				return NULL;
			}
		}

		nm_setting_vpn_remove_data_item (sanitized, params[i].name);
	}

	*out_con_name = g_steal_pointer (&con_name);
	return g_steal_pointer (&sanitized);
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

gboolean
nm_libreswan_parse_subnets (const char *str,
                            GPtrArray *arr,
                            GError **error)
{
	gs_strfreev char **tokens = NULL;
	char *addr;
	int prefix;
	int i;

	g_return_val_if_fail (str != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	tokens = g_strsplit_set (str, ", \t\n\v", 0);
	for (i = 0; tokens[i] != NULL; i++) {
		if (*tokens[i] == '\0')
			continue;
		if (   nm_utils_parse_inaddr_prefix (AF_INET, tokens[i], &addr, &prefix) == FALSE
		    && nm_utils_parse_inaddr_prefix (AF_INET6, tokens[i], &addr, &prefix) == FALSE) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
			             "'%s' is not a valid IP subnet", tokens[i]);
			return FALSE;
		}
		if (arr) {
			if (prefix == -1) {
				g_ptr_array_add (arr, g_strdup_printf ("%s", addr));
			} else {
				g_ptr_array_add (arr, g_strdup_printf ("%s/%d", addr, prefix));
			}
		}
		g_free (addr);
	}

	return TRUE;
}

char *
nm_libreswan_normalize_subnets (const char *str,
                                GError **error)
{
	gs_unref_ptrarray GPtrArray *arr = NULL;

	g_return_val_if_fail (str != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	arr = g_ptr_array_new_full (5, g_free);
	if (nm_libreswan_parse_subnets (str, arr, error) == FALSE)
		return NULL;
	g_ptr_array_add (arr, NULL);

	return g_strjoinv (",", (char **)arr->pdata);
}
