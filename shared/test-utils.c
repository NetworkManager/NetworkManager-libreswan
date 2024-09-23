#include "nm-default.h"

#include "utils.h"

#include <gio/gfiledescriptorbased.h>

static char *
_setting_into_ipsec_conf (NMSetting *s_vpn, const char *name, GError **error)
{
	gs_unref_object NMConnection *connection = NULL;
	gs_unref_object GFile *tmp = NULL;
	GFileIOStream *tmpstream;
	char buf[4096];
	gboolean res;
	gsize count;
	gint fd;

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection, s_vpn);

	tmp = g_file_new_tmp (NULL, &tmpstream, error);
	if (tmp == NULL)
		return NULL;

	res = g_file_delete (tmp, NULL, error);
	if (res == FALSE)
		return NULL;

	fd = g_file_descriptor_based_get_fd(G_FILE_DESCRIPTOR_BASED(
		g_io_stream_get_output_stream(G_IO_STREAM (tmpstream))));

	res = nm_libreswan_config_write (fd, 4, connection,
	                                 name, NULL,
	                                 FALSE, TRUE, NULL,
	                                 error);
	if (res == FALSE)
		return NULL;

	res = g_seekable_seek (G_SEEKABLE(tmpstream),
	                       0, G_SEEK_SET, NULL, error);
	if (res == FALSE)
		return NULL;

	res = g_input_stream_read_all (
		g_io_stream_get_input_stream(G_IO_STREAM (tmpstream)),
		buf,
		sizeof(buf)-1,
		&count,
		NULL,
		error);
	if (res == FALSE)
		return NULL;

	buf[count] = '\0';
	return g_strdup(buf);
}

static void
test_config_write (void)
{
	GError *error = NULL;
	NMSetting *s_vpn;
	char *str;

	s_vpn = nm_setting_vpn_new ();
	nm_setting_vpn_add_data_item (NM_SETTING_VPN(s_vpn), "right", "11.12.13.14");
	str = _setting_into_ipsec_conf (s_vpn, "con_name", &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn con_name\n"
	                 " authby=secret\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " right=11.12.13.14\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " leftxauthclient=yes\n"
	                 " remote-peer-type=cisco\n"
	                 " rightxauthserver=yes\n"
	                 " ikelifetime=24h\n"
	                 " salifetime=24h\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " ikev2=never\n"
	                 " nm-configured=yes\n"
	                 " auto=add\n");
	g_free (str);

	s_vpn = nm_setting_vpn_new ();
	nm_setting_vpn_add_data_item (NM_SETTING_VPN(s_vpn), "ikev2", "insist");
	nm_setting_vpn_add_data_item (NM_SETTING_VPN(s_vpn), "leftcert", "LibreswanClient");
	nm_setting_vpn_add_data_item (NM_SETTING_VPN(s_vpn), "leftid", "%fromcert");
	nm_setting_vpn_add_data_item (NM_SETTING_VPN(s_vpn), "right", "11.12.13.14");
	str = _setting_into_ipsec_conf (s_vpn,
	                                "f0008435-07af-4836-a53d-b43e8730e68f",
	                                &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==,
	                 "conn f0008435-07af-4836-a53d-b43e8730e68f\n"
	                 " leftid=%fromcert\n"
	                 " leftcert=LibreswanClient\n"
	                 " leftrsasigkey=%cert\n"
	                 " rightrsasigkey=%cert\n"
	                 " left=%defaultroute\n"
	                 " leftmodecfgclient=yes\n"
	                 " right=11.12.13.14\n"
	                 " rightmodecfgserver=yes\n"
	                 " modecfgpull=yes\n"
	                 " rightsubnet=0.0.0.0/0\n"
	                 " rekey=yes\n"
	                 " keyingtries=1\n"
	                 " ikev2=insist\n"
	                 " nm-configured=yes\n"
	                 " auto=add\n");
	g_free (str);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/utils/config/write", test_config_write);

	return g_test_run ();
}
