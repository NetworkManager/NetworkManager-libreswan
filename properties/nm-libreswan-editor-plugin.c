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
	gs_free char *ipsec_conf = NULL;
	gs_free char *con_name = NULL;
	NMSettingConnection *s_con;
	NMConnection *connection;
	NMSettingVpn *s_vpn;

	if (!g_file_get_contents (path, &ipsec_conf, NULL, error))
		return NULL;

	s_vpn = nm_libreswan_parse_ipsec_conf (ipsec_conf, &con_name, error);
	if (!s_vpn)
		return NULL;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, con_name, NULL);

	connection = nm_simple_connection_new ();
	nm_connection_add_setting (connection, NM_SETTING (s_con));
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	return connection;
}

static gboolean
export_to_file (NMVpnEditorPlugin *self,
                const char *path,
                NMConnection *connection,
                GError **error)
{
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	gboolean openswan = FALSE;
	gs_free_error GError *local = NULL;
	gs_free char *ipsec_conf = NULL;
	gboolean is_openswan;
	int version;

	s_vpn = get_setting_vpn_sanitized (connection, error);
	if (!s_vpn)
		return FALSE;

	openswan = nm_streq (nm_setting_vpn_get_service_type (s_vpn), NM_VPN_SERVICE_TYPE_OPENSWAN);

	nm_libreswan_detect_version (nm_libreswan_find_helper_bin ("ipsec", NULL),
	                             &is_openswan, &version, NULL);

	ipsec_conf = nm_libreswan_get_ipsec_conf (version, s_vpn,
	                                          nm_connection_get_id (connection),
	                                          NULL, openswan, TRUE, error);
	if (ipsec_conf == NULL)
		return FALSE;

	if (!g_file_set_contents (path, ipsec_conf, -1, &local)) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             _("Error writing to file “%s”: %s"), path, local->message);
		return FALSE;
	}

	return TRUE;
}

#if !NM_CHECK_VERSION(1, 52, 0)
#define NM_VPN_EDITOR_PLUGIN_CAPABILITY_NO_EDITOR 0x08
#endif

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	uint32_t capabilities;

	capabilities = NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT;
	capabilities |= NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT;
	if (LIBRESWAN_EDITOR_PLUGIN(iface)->module_path == NULL)
			capabilities |= NM_VPN_EDITOR_PLUGIN_CAPABILITY_NO_EDITOR;
	return capabilities;
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
	return nm_vpn_plugin_utils_load_editor (LIBRESWAN_EDITOR_PLUGIN(iface)->module_path,
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
dispose (GObject *object)
{
	LibreswanEditorPlugin *editor_plugin = LIBRESWAN_EDITOR_PLUGIN(object);

	g_clear_pointer (&editor_plugin->module_path, g_free);

	G_OBJECT_CLASS (libreswan_editor_plugin_parent_class)->dispose (object);
}

static void
libreswan_editor_plugin_class_init (LibreswanEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;
	object_class->dispose = dispose;

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
	LibreswanEditorPlugin *editor_plugin;
	gpointer gtk3_only_symbol;
	GModule *self_module;

	g_return_val_if_fail (!error || !*error, NULL);

	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

	self_module = g_module_open (NULL, 0);
	g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
	g_module_close (self_module);

	editor_plugin = g_object_new (LIBRESWAN_TYPE_EDITOR_PLUGIN, NULL);
	editor_plugin->module_path = nm_vpn_plugin_utils_get_editor_module_path
	        (gtk3_only_symbol ?
	         "libnm-vpn-plugin-libreswan-editor.so" :
	         "libnm-gtk4-vpn-plugin-libreswan-editor.so",
	         NULL);

	return NM_VPN_EDITOR_PLUGIN(editor_plugin);
}
