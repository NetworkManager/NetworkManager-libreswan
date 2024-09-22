#include "nm-default.h"

#include "utils.h"

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
	                 " authby=secret\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " leftxauthclient=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightxauthserver=yes\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " keyingtries=1\n"
	                 " rekey=yes\n"
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
	                 " leftrsasigkey=\"%cert\"\n"
	                 " rightrsasigkey=\"%cert\"\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " keyingtries=1\n"
	                 " rekey=yes\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n");
	g_free (str);
	g_object_unref (s_vpn);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/utils/config/write", test_config_write);

	return g_test_run ();
}
