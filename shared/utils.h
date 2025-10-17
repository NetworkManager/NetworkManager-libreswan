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

#ifndef __UTILS_H__
#define __UTILS_H__

char *nm_libreswan_get_ipsec_conf (int ipsec_version,
                                   NMSettingVpn *s_vpn,
                                   const char *con_name,
                                   const char *leftupdown_script,
                                   gboolean openswan,
                                   gboolean trailing_newline,
                                   GError **error);

NMSettingVpn *nm_libreswan_parse_ipsec_conf (const char *ipsec_conf,
                                             char **con_name,
                                             GError **error);

gboolean nm_libreswan_check_value (const char *key,
                                   const char *val,
                                   GError **error);

static inline gboolean
nm_libreswan_utils_setting_is_ikev2 (NMSettingVpn *s_vpn)
{
	const char *ikev2;

	ikev2 = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2);
	return NM_IN_STRSET (ikev2,
	                     NM_LIBRESWAN_IKEV2_PROPOSE,
	                     NM_LIBRESWAN_IKEV2_YES,
	                     NM_LIBRESWAN_IKEV2_INSIST);
}

void
nm_libreswan_detect_version (const char *path,
                             gboolean *out_is_openswan,
                             int *out_version,
                             char **out_banner);

const char *nm_libreswan_find_helper_bin (const char *progname, GError **error);
const char *nm_libreswan_find_helper_libexec (const char *progname, GError **error);

gboolean nm_libreswan_parse_subnets (const char *str, GPtrArray *arr, GError **error);
char *nm_libreswan_normalize_subnets (const char *str, GError **error);

NMSettingVpn *sanitize_setting_vpn (NMSettingVpn *s_vpn, GError **error);
NMSettingVpn *get_setting_vpn_sanitized (NMConnection *connection, GError **error);


#endif /* __UTILS_H__ */
