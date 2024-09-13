/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2010 Avesh Agarwal, <avagarwa@redhat.com>
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

#ifndef __NM_LIBRESWAN_EDITOR_PLUGIN_H__
#define __NM_LIBRESWAN_EDITOR_PLUGIN_H__

#define LIBRESWAN_TYPE_EDITOR_PLUGIN            (libreswan_editor_plugin_get_type ())
#define LIBRESWAN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), LIBRESWAN_TYPE_EDITOR_PLUGIN, LibreswanEditorPlugin))
#define LIBRESWAN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), LIBRESWAN_TYPE_EDITOR_PLUGIN, LibreswanEditorPluginClass))
#define LIBRESWAN_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), LIBRESWAN_TYPE_EDITOR_PLUGIN))
#define LIBRESWAN_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), LIBRESWAN_TYPE_EDITOR_PLUGIN))
#define LIBRESWAN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), LIBRESWAN_TYPE_EDITOR_PLUGIN, LibreswanEditorPluginClass))

typedef struct _LibreswanEditorPlugin LibreswanEditorPlugin;
typedef struct _LibreswanEditorPluginClass LibreswanEditorPluginClass;

struct _LibreswanEditorPlugin {
	GObject parent;
	char *module_path;
};

struct _LibreswanEditorPluginClass {
	GObjectClass parent;
};

GType libreswan_editor_plugin_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

NMVpnEditor *
nm_vpn_editor_factory_libreswan (NMVpnEditorPlugin *editor_plugin,
                                 NMConnection *connection,
                                 GError **error);

#endif /* __NM_LIBRESWAN_EDITOR_PLUGIN_H__ */
