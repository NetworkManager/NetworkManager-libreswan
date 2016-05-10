/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-libreswan.c : GNOME UI dialogs for configuring libreswan VPN connections
 *
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

#include "nm-libreswan.h"

#define LIBRESWAN_PLUGIN_NAME    _("IPsec based VPN")
#define LIBRESWAN_PLUGIN_DESC    _("IPsec based VPN using IKEv1")

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
	int fd;

	fd = g_open (path, O_RDONLY, 0777);
	if (fd == -1) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0,
		             _("Can't open file '%s': %s"), path, g_strerror (errno));
		return FALSE;
	}

	connection = nm_libreswan_config_read (fd);
	g_close (fd, NULL);

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
	int fd;

	fd = g_open (path, O_WRONLY | O_CREAT, 0777);
	if (fd == -1) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0,
		             _("Can't open file '%s': %s"), path, g_strerror (errno));
		return FALSE;
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		openswan = nm_streq (nm_setting_vpn_get_service_type (s_vpn), NM_VPN_SERVICE_TYPE_OPENSWAN);

	nm_libreswan_config_write (fd, connection, NULL, openswan);

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
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_editor_new (connection, error);
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

