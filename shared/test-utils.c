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
	char *str;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "con_name", NULL, FALSE, TRUE, &error);
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

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "dhgroup", "ignored");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "con_name", NULL, FALSE, TRUE, &error);
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

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "insist");
	nm_setting_vpn_add_data_item (s_vpn, "leftcert", "LibreswanClient");
	nm_setting_vpn_add_data_item (s_vpn, "leftid", "%fromcert");
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn,
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
	                 " phase2alg=aes256-sha1\n"
	                 " keyingtries=1\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "insist");
	nm_setting_vpn_add_data_item (s_vpn, "leftrsasigkey", "hello");
	nm_setting_vpn_add_data_item (s_vpn, "rightrsasigkey", "world");
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "conn", NULL, FALSE, TRUE, &error);
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
	                 " phase2alg=aes256-sha1\n"
	                 " keyingtries=1\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	str = nm_libreswan_get_ipsec_conf (3, s_vpn,
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

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "conn", NULL, FALSE, TRUE, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (str);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12.13.14");
	nm_setting_vpn_add_data_item (s_vpn, "ikev2", "hello world");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "conn", NULL, FALSE, TRUE, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (str);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "right", "11.12\n13.14");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "conn", NULL, FALSE, TRUE, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (str);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_setting_vpn_add_data_item (s_vpn, "rightcert", "\"cert\"");
	str = nm_libreswan_get_ipsec_conf (4, s_vpn, "conn", NULL, FALSE, TRUE, &error);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT);
	g_assert_null (str);
	g_clear_error (&error);
	g_object_unref (s_vpn);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/utils/config/write", test_config_write);

	return g_test_run ();
}
