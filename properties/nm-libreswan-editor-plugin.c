/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2005 David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 - 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
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
 **************************************************************************/

#include "nm-default.h"

#include "nm-libreswan-editor-plugin.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>

#include "utils.h"

#include "nm-utils/nm-vpn-plugin-utils.h"

#define LIBRESWAN_PLUGIN_NAME    _("IPsec based VPN")
#define LIBRESWAN_PLUGIN_DESC    _("IPsec based VPN for remote clients")

/*****************************************************************************/

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void libreswan_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (LibreswanEditorPlugin, libreswan_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               libreswan_editor_plugin_interface_init))

/*****************************************************************************/

static NMConnection *
import_from_file (NMVpnEditorPlugin *self,
                  const char *path,
                  GError **error)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	GIOChannel *chan;
	char *str_tmp;
	int fd, errsv;
	gboolean has_conn = FALSE;
	gboolean has_ikev2 = FALSE;
	gboolean is_ikev2 = TRUE;
	gboolean is_aggrmode = FALSE;
	gboolean is_default_aggr_ike = FALSE;
	gboolean is_default_aggr_esp = FALSE;
	gboolean is_default_ikev1_ikelifetime = FALSE;
	gboolean is_default_ikev1_salifetime = FALSE;
	/*
	 * All the booleans here are used to track if we are dealing with an IKEv1 configuration
	 * in aggressive mode: in IKEv1 we enforce our own defaults to libreswan for the "ikelifetime"
	 * and "salifetime" parameters; similarly, for IKEv1 connection in aggressive mode we enforce
	 * our own ike and esp chiper suites.
	 * Things got complicated because for IKEv2 connections we let Libreswan to pick up the default
	 * values: so, our defaults for IKEv1 when applied to IKEv2 connections are particular values
	 * that we have to add to the configuration.
	 * So, track when we hit default IKEv1 values and decide after having read the whole config if
	 * we need to track them in the NM config or not.
	 */

	fd = g_open (path, O_RDONLY, 0777);
	if (fd == -1) {
		errsv = errno;
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0,
		             _("Can’t open file “%s”: %s"), path, g_strerror (errsv));
		return NULL;
	}

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN, NULL);

	chan = g_io_channel_unix_new (fd);
	while (g_io_channel_read_line (chan, &str_tmp, NULL, NULL, NULL) == G_IO_STATUS_NORMAL) {
		gs_free char *str = str_tmp;

		g_strstrip (str);
		if (g_str_has_prefix (str, "conn ")) {
			if (has_conn) {
				/* only accept the first connection section */
				break;
			}
			has_conn = TRUE;
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, &str[5], NULL);
		} else if (g_str_has_prefix (str, "leftid=")) {
			if (str[7] == '@')
				is_aggrmode = TRUE;
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_LIBRESWAN_KEY_LEFTID,
			                              is_aggrmode ? &str[8] : &str[7]);
		} else if (g_str_has_prefix (str, "rightid=")) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              NM_LIBRESWAN_KEY_RIGHTID,
			                              (str[8] == '@') ? &str[9] : &str[8]);
		} else if (g_str_has_prefix (str, "ikev2=")) {
			const char *ikev2 = &str[6];

			has_ikev2 = TRUE;
			if (NM_IN_STRSET (ikev2,
			                  NM_LIBRESWAN_IKEV2_NO,
			                  NM_LIBRESWAN_IKEV2_NEVER)) {
				is_ikev2 = FALSE;
			} else
				is_ikev2 = TRUE;
			if (!nm_streq (ikev2, NM_LIBRESWAN_IKEV2_NEVER))
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2, ikev2);
		} else if (g_str_has_prefix (str, "ike=")) {
			const char *ike = &str[4];

			if (nm_streq (ike, NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE))
				is_default_aggr_ike = TRUE;
			else
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE, ike);
		} else if (g_str_has_prefix (str, "esp=")) {
			const char *esp = &str[4];

			if (nm_streq (esp, NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP))
				is_default_aggr_esp = TRUE;
			else
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP, esp);
		} else if (g_str_has_prefix (str, "phase2alg=")) {
			const char *esp = &str[10];

			if (nm_streq (esp, NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP))
				is_default_aggr_esp = TRUE;
			else
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP, esp);
		} else if (g_str_has_prefix (str, "ikelifetime=")) {
			const char *lifetime = &str[12];

			if (nm_streq (lifetime, NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME))
				is_default_ikev1_ikelifetime = TRUE;
			else
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKELIFETIME, lifetime);
		} else if (g_str_has_prefix (str, "salifetime=")) {
			const char *lifetime = &str[11];

			if (nm_streq (lifetime, NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME))
				is_default_ikev1_salifetime = TRUE;
			else
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_SALIFETIME, lifetime);
		} else if (g_str_has_prefix (str, "left=")) {
			if (!nm_streq (str, "left=%defaultroute"))
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFT, &str[5]);
		} else if (g_str_has_prefix (str, "right="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT, &str[6]);
		else if (g_str_has_prefix (str, "leftxauthusername="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER, &str[18]);
		else if (g_str_has_prefix (str, "leftusername="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTUSERNAME, &str[13]);
		else if (g_str_has_prefix (str, "leftcert="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT, &str[9]);
		else if (g_str_has_prefix (str, "pfs=no"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_PFS, "no");
		else if (g_str_has_prefix (str, "cisco-unity=yes"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_VENDOR, "Cisco");
		else if (g_str_has_prefix (str, "rekey=no"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY, "no");
		else if (g_str_has_prefix (str, "narrowing="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_NARROWING, &str[10]);
		else if (g_str_has_prefix (str, "fragmentation="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, &str[14]);
		else if (g_str_has_prefix (str, "mobike="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_MOBIKE, &str[7]);
		else if (g_str_has_prefix (str, "rightsubnet=")) {
			if (!g_str_has_prefix (str, "rightsubnet=0.0.0.0/0"))
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REMOTENETWORK, &str[12]);
		} else if (g_str_has_prefix (str, "leftrsasigkey=")) {
			if (str[14] != '%')
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY, &str[14]);
		} else if (g_str_has_prefix (str, "rightrsasigkey=")) {
			if (str[15] != '%')
				nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY, &str[15]);
		} else {
			/* till we don't get an explicit ikev2 value get hints on IKE version:
			 * libreswan changed the default from IKEv1 to IKEv2 but older NM version
			 * assumed IKEv1 as default... we should guess smart if we don't get an
			 * explicit ikev2 value. */
			if (   !has_ikev2
			    && (   nm_streq (str, "aggrmode=yes")
			        || nm_streq (str, "leftxauthclient=yes")
			        || nm_streq (str, "rightxauthserver=yes"))) {
				is_ikev2 = FALSE;
			}
			/* unknown tokens are silently ignored. */
		}
	}
	g_io_channel_unref (chan);

	g_close (fd, NULL);

	if (!has_conn) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN,
		             _("Missing “conn” section in “%s”"), path);
		g_object_unref (connection);
		return NULL;
	}

	if (!has_ikev2 && is_ikev2)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2, NM_LIBRESWAN_IKEV2_YES);

	if (is_ikev2) {
		is_aggrmode = FALSE;
		if (is_default_ikev1_ikelifetime) {
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKELIFETIME,
			                              NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME);
		}
		if (is_default_ikev1_salifetime) {
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_SALIFETIME,
			                              NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME);
		}
	}
	if (!is_aggrmode) {
		if (is_default_aggr_ike) {
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE,
			                              NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE);
		}
		if (is_default_aggr_esp) {
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP,
			                              NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP);
		}
	}

	return connection;
}

static gboolean
export_to_file (NMVpnEditorPlugin *self,
                const char *path,
                NMConnection *connection,
                GError **error)
{
	NMSettingVpn *s_vpn;
	gboolean openswan = FALSE;
	int fd, errsv;
	gs_free_error GError *local = NULL;
	gboolean is_openswan;
	int version;

	fd = g_open (path, O_WRONLY | O_CREAT, 0666);
	if (fd == -1) {
		errsv = errno;
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             _("Can’t open file “%s”: %s"), path, g_strerror (errsv));
		return FALSE;
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		openswan = nm_streq (nm_setting_vpn_get_service_type (s_vpn), NM_VPN_SERVICE_TYPE_OPENSWAN);

	nm_libreswan_detect_version (nm_libreswan_find_helper_bin ("ipsec", NULL),
	                             &is_openswan, &version, NULL);

	if (!nm_libreswan_config_write (fd,
	                                version,
	                                connection,
	                                nm_connection_get_id (connection),
	                                NULL,
	                                openswan,
	                                TRUE,
	                                NULL,
	                                &local)) {
		g_close (fd, NULL);
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             _("Error writing to file “%s”: %s"), path, local->message);
		return FALSE;
	}

	if (!g_close (fd, error))
		return FALSE;

	return TRUE;
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT;
}

static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	gpointer gtk3_only_symbol;
	GModule *self_module;
	const char *editor;

	g_return_val_if_fail (LIBRESWAN_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

        self_module = g_module_open (NULL, 0);
        g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
        g_module_close (self_module);

	if (gtk3_only_symbol) {
		editor = "libnm-vpn-plugin-libreswan-editor.so";
	} else {
		editor = "libnm-gtk4-vpn-plugin-libreswan-editor.so";
	}

	return nm_vpn_plugin_utils_load_editor (editor,
						"nm_vpn_editor_factory_libreswan",
						_call_editor_factory,
						iface,
						connection,
						NULL,
						error);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, LIBRESWAN_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, LIBRESWAN_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, NM_VPN_SERVICE_TYPE_LIBRESWAN);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
libreswan_editor_plugin_class_init (LibreswanEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
	                                  PROP_NAME,
	                                  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  PROP_DESC,
	                                  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
	                                  PROP_SERVICE,
	                                  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
libreswan_editor_plugin_init (LibreswanEditorPlugin *plugin)
{
}

static void
libreswan_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;

	iface_class->import_from_file = import_from_file;
	iface_class->export_to_file = export_to_file;

	iface_class->get_suggested_filename = NULL;
}


G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	return g_object_new (LIBRESWAN_TYPE_EDITOR_PLUGIN, NULL);
}

