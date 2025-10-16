/* NetworkManager-libreswan -- Network Manager Libreswan plugin
 *
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
 * Copyright (C) 2024 Red Hat, Inc.
 */

#include "nm-default.h"

#include "utils.h"

#include "nm-utils/nm-shared-utils.h"

static void
test_config_write (void)
{
	GError *error = NULL;
	NMSettingVpn *s_vpn;
	NMSettingVpn *s_vpn_sanitized;
	char *str;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "con_name", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn con_name\n"
	                 " ikev2=never\n"
	                 " right=11.12.13.14\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " authby=secret\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " leftxauthclient=yes\n"
	                 " rightxauthserver=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "dhgroup", "ignored");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "con_name", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn con_name\n"
	                 " ikev2=never\n"
	                 " right=11.12.13.14\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " authby=secret\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " leftxauthclient=yes\n"
	                 " rightxauthserver=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");

	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "insist");
	nm_setting_vpn_add_data_item (s_vpn, "leftcert", "LibreswanClient");
	nm_setting_vpn_add_data_item (s_vpn, "leftid", "%fromcert");
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized,
	                                   "f0008435-07af-4836-a53d-b43e8730e68f",
			                   NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn f0008435-07af-4836-a53d-b43e8730e68f\n"
	                 " ikev2=insist\n"
	                 " right=11.12.13.14\n"
	                 " leftid=%fromcert\n"
	                 " leftcert=\"LibreswanClient\"\n"
	                 " rightrsasigkey=\"%cert\"\n"
	                 " leftrsasigkey=\"%cert\"\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "insist");
	nm_setting_vpn_add_data_item (s_vpn, "leftrsasigkey", "hello");
	nm_setting_vpn_add_data_item (s_vpn, "rightrsasigkey", "world");
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "conn", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn conn\n"
	                 " ikev2=insist\n"
	                 " right=11.12.13.14\n"
	                 " rightrsasigkey=\"world\"\n"
	                 " leftrsasigkey=\"hello\"\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (3, s_vpn_sanitized,
	                                   "my_con",
			                   "/foo/bar/ifupdown hello 123 456",
	                                   TRUE, FALSE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn my_con\n"
	                 " ikev2=never\n"
	                 " right=11.12.13.14\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " authby=secret\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " leftxauthclient=yes\n"
	                 " rightxauthserver=yes\n"
	                 " remote_peer_type=cisco\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n"
	                 " leftupdown=\"/foo/bar/ifupdown hello 123 456\"\n"
	                 " auto=add\n"
	                 " nm-configured=yes");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "insist");
	nm_setting_vpn_add_data_item (s_vpn, "leftrsasigkey", "hello");
	nm_setting_vpn_add_data_item (s_vpn, "rightrsasigkey", "world");
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "nm-auto-defaults", "no");
	nm_setting_vpn_add_data_item (s_vpn, "leftsendcert", "always");
	nm_setting_vpn_add_data_item (s_vpn, "rightca", "%same");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "conn", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
                         "# NetworkManager specific configs, don't remove:\n"
                         "# nm-auto-defaults=no\n"
                         "\n"
                         "conn conn\n"
                         " ikev2=insist\n"
                         " right=11.12.13.14\n"
                         " rightrsasigkey=\"world\"\n"
                         " leftrsasigkey=\"hello\"\n"
                         " leftsendcert=always\n"
                         " rightca=\"%same\"\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "esp", "aes_gcm256");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "con_name", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn con_name\n"
	                 " ikev2=never\n"
	                 " right=11.12.13.14\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " authby=secret\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " esp=aes_gcm256\n"
	                 " phase2alg=aes_gcm256\n"
	                 " keyingtries=1\n"
	                 " leftxauthclient=yes\n"
	                 " rightxauthserver=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "vendor", "Cisco");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_no_error (error);
	str = nm_libreswan_get_ipsec_conf (4, s_vpn_sanitized, "con_name", NULL, FALSE, TRUE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn con_name\n"
	                 " ikev2=never\n"
	                 " right=11.12.13.14\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " authby=secret\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " cisco-unity=yes\n"
	                 " keyingtries=1\n"
	                 " leftxauthclient=yes\n"
	                 " rightxauthserver=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
	g_object_unref (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);
	g_object_unref (s_vpn);
	g_assert_null (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "hello world");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);
	g_object_unref (s_vpn);
	g_assert_null (s_vpn_sanitized);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12\n13.14");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn_sanitized);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "rightcert", "\"cert\"");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn_sanitized);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "nm-auto-defaults", "no");
	nm_setting_vpn_add_data_item (s_vpn, "rightcert", "\"cert\"");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn_sanitized);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "nm-auto-defaults", "no");
	s_vpn_sanitized = sanitize_setting_vpn (s_vpn, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn_sanitized);
	g_clear_error (&error);
	g_object_unref (s_vpn);
}

static void
test_config_read (void)
{
	char *con_name = NULL;
	GError *error = NULL;
	NMSettingVpn *s_vpn;

	/* Minimal. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* Also include all generated properties. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" salifetime=24h\n"
		" rightsubnet=0.0.0.0/0\n"
		" right=11.12.13.14\n"
		" rekey=yes\n"
		" leftmodecfgclient=yes\n"
		" left=%defaultroute\n"
		" ikev2=never\n"
		" ikelifetime=24h\n"
		" authby=secret\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* Include all synthetic properties with appropriate values. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
	        "conn xpl\n"
	        " ikev2=never\n"
	        " right=172.31.79.2\n"
	        " leftid=@groupname\n"
	        " left=%defaultroute\n"
	        " leftmodecfgclient=yes\n"
	        " authby=secret\n"
	        " ike=aes256-sha1;modp1536\n"
	        " ikelifetime=24h\n"
	        " salifetime=24h\n"
	        " rightsubnet=10.0.2.0/24\n"
	        " leftusername=\"username\"\n"
	        " rekey=yes\n"
	        " keyingtries=1\n"
	        " aggrmode=yes\n"
	        " leftxauthclient=yes\n"
	        " rightxauthserver=yes\n"
	        " remote-peer-type=cisco\n"
	        " rightmodecfgserver=yes\n"
	        " modecfgpull=yes\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 12);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ike"),			==, "aes256-sha1;modp1536");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftid"),		==, "@groupname");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftusername"),		==, "username");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "172.31.79.2");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "10.0.2.0/24");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn con_name\n"
		" ikev2=never\n"
		" right=11.12.13.14\n"
		" left=%defaultroute\n"
		" leftmodecfgclient=yes\n"
		" authby=secret\n"
		" ikelifetime=24h\n"
		" salifetime=24h\n"
		" rightsubnet=0.0.0.0/0\n"
		" rekey=yes\n"
		" keyingtries=1\n"
		" leftxauthclient=yes\n"
		" rightxauthserver=yes\n"
		" remote-peer-type=cisco\n"
		" rightmodecfgserver=yes\n"
		" modecfgpull=yes\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (con_name, ==, "con_name");
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		 "conn f0008435-07af-4836-a53d-b43e8730e68f\n"
		 " ikev2=insist\n"
		 " right=11.12.13.14\n"
		 " leftcert=\"Libreswan Client\"\n"
		 " rightrsasigkey=\"%cert\"\n"
		 " leftrsasigkey=%cert\n"
		 " left=%defaultroute\n"
		 " leftmodecfgclient=yes\n"
		 " rightsubnet=0.0.0.0/0\n"
		 " rekey=yes\n"
		 " keyingtries=1\n"
		 " rightmodecfgserver=yes\n"
		 " modecfgpull=yes\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (con_name, ==, "f0008435-07af-4836-a53d-b43e8730e68f");
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "insist");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftcert"),		==, "Libreswan Client");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftrsasigkey"),		==, "%cert");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightrsasigkey"),	==, "%cert");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" ikev2=insist\n"
		" right=11.12.13.14\n"
		" rightrsasigkey=\"world\"\n"
		" leftrsasigkey=\"hello\"\n"
		" left=%defaultroute\n"
		" leftmodecfgclient=yes\n"
		" rightsubnet=0.0.0.0/0\n"
		" rekey=yes\n"
		" esp=aes256-sha1\n"
		" keyingtries=1\n"
		" rightmodecfgserver=yes\n"
		" modecfgpull=yes\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (con_name, ==, "conn");
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "insist");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftrsasigkey"),		==, "hello");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightrsasigkey"),	==, "world");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn con_name\n"
		" ikev2=never\n"
		" right=11.12.13.14\n"
		" left=%defaultroute\n"
		" leftmodecfgclient=yes\n"
		" authby=secret\n"
		" ikelifetime=24h\n"
		" rekey=yes\n"
		" rightsubnet=0.0.0.0/0\n"
		" salifetime=24h\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (con_name, ==, "con_name");
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"# This configuration was created unded influence.\r\n"
		"# Do not edit!\n\r"
		"\n"
		"    # the # below doesn't introduce a comment  \n"
		"conn con#name\n"
		"# comments are preceded by whitespace\n"
		"\t\n"
		" ikev2=never\n"
		" left=\t\t%defaultroute\n"
		"\t# moo"
		"\tleftmodecfgclient  = \t yes\n"
		" authby=\"secret\"\n"
		"# boo"
		"    ikelifetime =24h   # what\n"
		"  \t rekey=yes\n"
		"\n"
		" rightsubnet=\t0.0.0.0/0\n"
		"   #wot\r"
		" \tright=11.12.13.14\n"
		" \t\tsalifetime=24h",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (con_name, ==, "con#name");
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 9);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* Make sure properties with right synthetic values are allowed. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n"
		" cisco-unity=yes\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 10);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "vendor"),		==, "Cisco");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* Synchronize esp and phase2alg. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n"
		" phase2alg=aes128-sha2_512;dh19\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpint (nm_setting_vpn_get_num_data_items (s_vpn), ==, 10);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "authby"),		==, "secret");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikelifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"),			==, "never");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "left"),			==, "%defaultroute");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftmodecfgclient"),	==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rekey"),			==, "yes");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"),			==, "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightsubnet"),		==, "0.0.0.0/0");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "salifetime"),		==, "24h");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "esp"),			==, "aes128-sha2_512;dh19");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* With the '# nm-auto-defaults=no' special comment */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"# nm-auto-defaults=no\n"
		"conn conn\n"
		" ikev2=insist\n"
		" right=11.12.13.14\n"
		" rightrsasigkey=\"world\"\n"
		" leftrsasigkey=\"hello\"\n"
		" leftsendcert=always\n"
		" rightca=\"%same\"\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"), ==, "insist");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftrsasigkey"), == , "hello");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightrsasigkey"), == , "world");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"), == , "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "nm-auto-defaults"), == , "no");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftsendcert"), == , "always");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightca"), == , "%same");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightca"), == , "%same");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	/* With the '# nm-auto-defaults=no' special comment, different spacing */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"#nm-auto-defaults  	= 	 no  	 \n"
		"conn conn\n"
		" ikev2=insist\n"
		" right=11.12.13.14\n"
		" rightrsasigkey=\"world\"\n"
		" leftrsasigkey=\"hello\"\n"
		" leftsendcert=always\n"
		" rightca=\"%same\"\n",
		&con_name,
		&error);
	g_assert_no_error (error);
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "ikev2"), ==, "insist");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftrsasigkey"), == , "hello");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightrsasigkey"), == , "world");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "right"), == , "11.12.13.14");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "nm-auto-defaults"), == , "no");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "leftsendcert"), == , "always");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightca"), == , "%same");
	g_assert_cmpstr (nm_setting_vpn_get_data_item (s_vpn, "rightca"), == , "%same");
	g_object_unref (s_vpn);
	g_clear_pointer (&con_name, g_free);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		" right=11.12.13.14\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		"right=11.12.13.14\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		" right=11.12.13.14\n"
		"conn my_con\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		" right=11.12.13.14\n"
		"conn my_con\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		" right=11.12.13.14\n"
		" right=11.12.13.14\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	/* Not an actual property */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		" right=11.12.13.14\n"
		" hola=prdel\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		" right=11.12.13.14\n"
		" leftcert=Libreswan Client\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn my_con\n"
		" ikev2=never\n"
		" right=11.12.13.14\n"
		" left=%defaultroute\n"
		" leftmodecfgclient=yes\n"
		" authby=secret\n"
		" ikelifetime=24h\n"
		" salifetime=24h\n"
		" rightsubnet=0.0.0.0/0\n"
		" rekey=yes\n"
		" keyingtries=1\n"
		" leftxauthclient=yes\n"
		" rightxauthserver=yes\n"
		" remote_peer_type=cisco\n"
		" rightmodecfgserver=yes\n"
		" modecfgpull=yes\n"
		" leftupdown=\"/foo/bar/ifupdown hello 123 456\"\n"
		" auto=add\n"
		" nm-configured=yes",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	/* Make sure synthetic properties can't be overriden. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n"
		" rightmodecfgserver=no\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	/* Make sure internal properties are rejected when importing. */
	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n"
		" nm-auto-defaults=no\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);

	s_vpn = nm_libreswan_parse_ipsec_conf (
		"conn conn\n"
		" right=11.12.13.14\n"
		" vendor=Cisco\n",
		&con_name,
		&error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (s_vpn);
	g_assert_null (con_name);
	g_clear_error (&error);
}

static void
test_parse_subnets (void)
{
	GError *error = NULL;
	gboolean ret;

	/*
	 * Positive cases.
	 */

	ret = nm_libreswan_parse_subnets ("", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1,10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24,10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16,,", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16", NULL, &error);
	g_assert (ret);
	g_assert_no_error (error);

	/*
	 * Negative cases.
	 */

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24meh", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24meh,10.10.0.0/16", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16meh", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16,a", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1/24, 10.10.0.0/16,b", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("10.0.0.1, 10.10.0.0/16,a,", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	ret = nm_libreswan_parse_subnets ("boo, 10.0.0.1/24, 10.10.0.0/16", NULL, &error);
	g_assert_false (ret);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	/*
	 * No GError.
	 */

	ret = nm_libreswan_parse_subnets ("", NULL, NULL);
	g_assert (ret);

	ret = nm_libreswan_parse_subnets ("boo", NULL, NULL);
	g_assert_false (ret);
}

static void
test_normalize_subnets (void)
{
	GError *error = NULL;
	gchar *str;

	/*
	 * Positive cases.
	 */

	str = nm_libreswan_normalize_subnets ("", &error);
	g_assert_cmpstr (str, ==, "");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1,10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24,10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16,,", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16", &error);
	g_assert_cmpstr (str, ==, "10.0.0.1/24,10.10.0.0/16");
	g_assert_no_error (error);
	g_free (str);

	/*
	 * Negative cases.
	 */

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24meh", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24meh,10.10.0.0/16", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16meh", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16,a", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1/24, 10.10.0.0/16,b", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("10.0.0.1, 10.10.0.0/16,a,", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	str = nm_libreswan_normalize_subnets ("boo, 10.0.0.1/24, 10.10.0.0/16", &error);
	g_assert_null (str);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_clear_error (&error);

	/*
	 * No GError.
	 */

	str = nm_libreswan_normalize_subnets ("", NULL);
	g_assert_cmpstr (str, ==, "");
	g_free (str);

	str = nm_libreswan_normalize_subnets ("boo", NULL);
	g_assert_null (str);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/utils/config/write", test_config_write);
	g_test_add_func ("/utils/config/read", test_config_read);
	g_test_add_func ("/utils/subnets/parse", test_parse_subnets);
	g_test_add_func ("/utils/subnets/normalize", test_normalize_subnets);

	return g_test_run ();
}
