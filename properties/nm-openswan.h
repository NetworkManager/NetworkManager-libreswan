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

typedef enum
{
	OPENSWAN_PLUGIN_UI_ERROR_UNKNOWN = 0,
	OPENSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	OPENSWAN_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	OPENSWAN_PLUGIN_UI_ERROR_INVALID_CONNECTION
} OpenswanPluginUiError;

#define OPENSWAN_TYPE_PLUGIN_UI_ERROR (openswan_plugin_ui_error_get_type ()) 
GType openswan_plugin_ui_error_get_type (void);

#define OPENSWAN_TYPE_PLUGIN_UI            (openswan_plugin_ui_get_type ())
#define OPENSWAN_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSWAN_TYPE_PLUGIN_UI, OpenswanPluginUi))
#define OPENSWAN_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSWAN_TYPE_PLUGIN_UI, OpenswanPluginUiClass))
#define OPENSWAN_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSWAN_TYPE_PLUGIN_UI))
#define OPENSWAN_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSWAN_TYPE_PLUGIN_UI))
#define OPENSWAN_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSWAN_TYPE_PLUGIN_UI, OpenswanPluginUiClass))

typedef struct _OpenswanPluginUi OpenswanPluginUi;
typedef struct _OpenswanPluginUiClass OpenswanPluginUiClass;

struct _OpenswanPluginUi {
	GObject parent;
};

struct _OpenswanPluginUiClass {
	GObjectClass parent;
};

GType openswan_plugin_ui_get_type (void);


#define OPENSWAN_TYPE_PLUGIN_UI_WIDGET            (openswan_plugin_ui_widget_get_type ())
#define OPENSWAN_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSWAN_TYPE_PLUGIN_UI_WIDGET, OpenswanPluginUiWidget))
#define OPENSWAN_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSWAN_TYPE_PLUGIN_UI_WIDGET, OpenswanPluginUiWidgetClass))
#define OPENSWAN_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSWAN_TYPE_PLUGIN_UI_WIDGET))
#define OPENSWAN_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSWAN_TYPE_PLUGIN_UI_WIDGET))
#define OPENSWAN_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSWAN_TYPE_PLUGIN_UI_WIDGET, OpenswanPluginUiWidgetClass))

typedef struct _OpenswanPluginUiWidget OpenswanPluginUiWidget;
typedef struct _OpenswanPluginUiWidgetClass OpenswanPluginUiWidgetClass;

struct _OpenswanPluginUiWidget {
	GObject parent;
};

struct _OpenswanPluginUiWidgetClass {
	GObjectClass parent;
};

GType openswan_plugin_ui_widget_get_type (void);

#endif	/* _NM_OPENSWAN_H_ */

