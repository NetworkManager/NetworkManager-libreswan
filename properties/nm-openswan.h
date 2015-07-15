/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openswan.h : GNOME UI dialogs for configuring openswan VPN connections
 *
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

#ifndef _NM_OPENSWAN_H_
#define _NM_OPENSWAN_H_

#include <glib-object.h>

#define OPENSWAN_TYPE_EDITOR_PLUGIN            (openswan_editor_plugin_get_type ())
#define OPENSWAN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSWAN_TYPE_EDITOR_PLUGIN, OpenswanEditorPlugin))
#define OPENSWAN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSWAN_TYPE_EDITOR_PLUGIN, OpenswanEditorPluginClass))
#define OPENSWAN_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSWAN_TYPE_EDITOR_PLUGIN))
#define OPENSWAN_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSWAN_TYPE_EDITOR_PLUGIN))
#define OPENSWAN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSWAN_TYPE_EDITOR_PLUGIN, OpenswanEditorPluginClass))

typedef struct _OpenswanEditorPlugin OpenswanEditorPlugin;
typedef struct _OpenswanEditorPluginClass OpenswanEditorPluginClass;

struct _OpenswanEditorPlugin {
	GObject parent;
};

struct _OpenswanEditorPluginClass {
	GObjectClass parent;
};

GType openswan_editor_plugin_get_type (void);


#define OPENSWAN_TYPE_EDITOR            (openswan_editor_get_type ())
#define OPENSWAN_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSWAN_TYPE_EDITOR, OpenswanEditor))
#define OPENSWAN_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSWAN_TYPE_EDITOR, OpenswanEditorClass))
#define OPENSWAN_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSWAN_TYPE_EDITOR))
#define OPENSWAN_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSWAN_TYPE_EDITOR))
#define OPENSWAN_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSWAN_TYPE_EDITOR, OpenswanEditorClass))

typedef struct _OpenswanEditor OpenswanEditor;
typedef struct _OpenswanEditorClass OpenswanEditorClass;

struct _OpenswanEditor {
	GObject parent;
};

struct _OpenswanEditorClass {
	GObjectClass parent;
};

GType openswan_editor_get_type (void);

#endif	/* _NM_OPENSWAN_H_ */

