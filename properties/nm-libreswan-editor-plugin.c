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

#ifdef NM_VPN_OLD
#include "nm-libreswan-editor.h"
#else
#include "nm-utils/nm-vpn-plugin-utils.h"
#endif

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
				/* only accept the frist connection section */
				break;
			}
			has_conn = TRUE;
			g_object_set (s_con, NM_SETTING_CONNECTION_ID, &str[5], NULL);
		}
		else if (g_str_has_prefix (str, "leftid=@"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTID, &str[8]);
		else if (g_str_has_prefix (str, "leftxauthusername="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER, &str[18]);
		else if (g_str_has_prefix (str, "right="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_RIGHT, &str[6]);
		else if (g_str_has_prefix (str, "ike=") && strcmp (str, "ike=aes-sha1"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_IKE, &str[4]);
		else if (g_str_has_prefix (str, "esp=") && strcmp (str, "esp=aes-sha1;modp1024"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_ESP, &str[4]);
		else if (g_str_has_prefix (str, "cisco-unity=yes"))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_VENDOR, "Cisco");
		else if (g_str_has_prefix (str, "ikelifetime="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_IKELIFETIME,
						      &str[12]);
		else if (g_str_has_prefix (str, "salifetime="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_SALIFETIME,
						      &str[11]);
		else if (g_str_has_prefix (str, "rightsubnet="))
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_REMOTENETWORK,
						      &str[12]);
		else {
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

	if (!nm_libreswan_config_write (fd,
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

#ifndef NM_VPN_OLD
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
#endif

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (LIBRESWAN_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	{
#ifdef NM_VPN_OLD
		return nm_vpn_editor_new (connection, error);
#else
		return nm_vpn_plugin_utils_load_editor (NM_PLUGIN_DIR"/libnm-vpn-plugin-libreswan-editor.so",
		                                        "nm_vpn_editor_factory_libreswan",
		                                        _call_editor_factory,
		                                        iface,
		                                        connection,
		                                        NULL,
		                                        error);
#endif
	}
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

