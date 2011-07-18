/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openswan.c : GNOME UI dialogs for configuring openswan VPN connections
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-openswan-service.h"
#include "nm-openswan.h"

#define OPENSWAN_PLUGIN_NAME    _("IPsec based VPN")
#define OPENSWAN_PLUGIN_DESC    _("IPsec, IKEv1, IKEv2 based VPN")
#define OPENSWAN_PLUGIN_SERVICE NM_DBUS_SERVICE_OPENSWAN 

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK	   1
#define PW_TYPE_UNUSED 2

/************** plugin class **************/

static void openswan_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenswanPluginUi, openswan_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   openswan_plugin_ui_interface_init))

/************** UI widget class **************/

static void openswan_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenswanPluginUiWidget, openswan_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   openswan_plugin_ui_widget_interface_init))

#define OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENSWAN_TYPE_PLUGIN_UI_WIDGET, OpenswanPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gint orig_dpd_timeout;
	gboolean new_connection;
} OpenswanPluginUiWidgetPrivate;


#define OPENSWAN_PLUGIN_UI_ERROR openswan_plugin_ui_error_quark ()

static GQuark
openswan_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("openswan-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
openswan_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (OPENSWAN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (OPENSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (OPENSWAN_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (OPENSWAN_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("OpenswanPluginUiError", values);
	}
	return etype;
}


static gboolean
check_validity (OpenswanPluginUiWidget *self, GError **error)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             OPENSWAN_PLUGIN_UI_ERROR,
		             OPENSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSWAN_RIGHT);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENSWAN_PLUGIN_UI_ERROR,
		             OPENSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSWAN_LEFTID);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENSWAN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
show_toggled_cb (GtkCheckButton *button, OpenswanPluginUiWidget *self)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
pw_type_changed_helper (OpenswanPluginUiWidget *self, GtkWidget *combo)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	const char *entry = NULL;
	GtkWidget *widget;

	/* If the user chose "Not required", desensitize and clear the correct
	 * password entry.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_pass_type_combo"));
	if (combo == widget)
		entry = "user_password_entry";
	else {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_pass_type_combo"));
		if (combo == widget)
			entry = "group_password_entry";
	}
	if (!entry)
		return;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry));
	g_assert (widget);

	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_ASK:
	case PW_TYPE_UNUSED:
		gtk_entry_set_text (GTK_ENTRY (widget), "");
		gtk_widget_set_sensitive (widget, FALSE);
		break;
	default:
		gtk_widget_set_sensitive (widget, TRUE);
		break;
	}
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	OpenswanPluginUiWidget *self = OPENSWAN_PLUGIN_UI_WIDGET (user_data);

	pw_type_changed_helper (self, combo);
	stuff_changed_cb (combo, self);
}

static const char *
secret_flags_to_pw_type (NMSettingVPN *s_vpn, const char *key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), key, &flags, NULL)) {
		if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			return NM_OPENSWAN_PW_TYPE_UNUSED;
		if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			return NM_OPENSWAN_PW_TYPE_ASK;
		return NM_OPENSWAN_PW_TYPE_SAVE;
	}
	return NULL;
}

static void
init_one_pw_combo (OpenswanPluginUiWidget *self,
                   NMSettingVPN *s_vpn,
                   const char *combo_name,
                   const char *secret_key,
                   const char *type_key,
                   const char *entry_name)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	int active = -1;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	guint32 default_idx = 1;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	if (widget) {
		const char *tmp;

		tmp = gtk_entry_get_text (GTK_ENTRY (widget));
		if (tmp && strlen (tmp))
			default_idx = 0;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	if (s_vpn) {
		value = secret_flags_to_pw_type (s_vpn, secret_key);
		if (!value)
			value = nm_setting_vpn_get_data_item (s_vpn, type_key);
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Saved"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_OPENSWAN_PW_TYPE_SAVE))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_OPENSWAN_PW_TYPE_ASK))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_OPENSWAN_PW_TYPE_UNUSED))
			active = 2;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, combo_name));
	g_assert (widget);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);
	pw_type_changed_helper (self, widget);

	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), self);
}

static gboolean
init_plugin_ui (OpenswanPluginUiWidget *self, NMConnection *connection, GError **error)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	const char *value = NULL;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_RIGHT);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTID);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Fill the VPN passwords *before* initializing the PW type combos, since
	 * knowing if there are passwords when initializing the combos is helpful.
	 */

	/* User password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_assert (widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
	}
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Group password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	g_assert (widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_PSK_VALUE);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
	}
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	init_one_pw_combo (self,
	                   s_vpn,
	                   "user_pass_type_combo",
	                   NM_OPENSWAN_XAUTH_PASSWORD,
	                   NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES,
	                   "user_password_entry");
	init_one_pw_combo (self,
	                   s_vpn,
	                   "group_pass_type_combo",
	                   NM_OPENSWAN_PSK_VALUE,
	                   NM_OPENSWAN_PSK_INPUT_MODES,
	                   "group_password_entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 1 Algorithms: IKE*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_IKE);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 2 Algorithms: ESP*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_ESP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/*widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_DPDTIMEOUT);
		if (value) {
			long int tmp;

			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (tmp >= 0 && tmp <= G_MAXUINT32 && errno == 0)
				priv->orig_dpd_timeout = (guint32) tmp;

			if (priv->orig_dpd_timeout == 0)
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
		}
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);*/

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	OpenswanPluginUiWidget *self = OPENSWAN_PLUGIN_UI_WIDGET (iface);
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static guint32
handle_one_pw_type (NMSettingVPN *s_vpn,
                    GtkBuilder *builder,
                    const char *combo_name,
                    const char *secret_key,
                    const char *type_key,
                    gboolean new_connection)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	GtkWidget *widget;
	guint32 pw_type;
	const char *data_val = NULL;

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &flags, NULL);
	flags &= ~(NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, combo_name));
	pw_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (pw_type) {
	case PW_TYPE_SAVE:
		data_val = NM_OPENSWAN_PW_TYPE_SAVE;
		break;
	case PW_TYPE_UNUSED:
		data_val = NM_OPENSWAN_PW_TYPE_UNUSED;
		flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;
		break;
	case PW_TYPE_ASK:
	default:
		pw_type = PW_TYPE_ASK;
		data_val = NM_OPENSWAN_PW_TYPE_ASK;
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		break;
	}

	if (new_connection) {
		/* new connections default to agent-owned secrets */
		flags |= NM_SETTING_SECRET_FLAG_AGENT_OWNED;
	}

	nm_setting_vpn_add_data_item (s_vpn, type_key, data_val);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), secret_key, flags, NULL);
	return pw_type;
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenswanPluginUiWidget *self = OPENSWAN_PLUGIN_UI_WIDGET (iface);
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	char *str;
	guint32 upw_type, gpw_type;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_OPENSWAN, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_RIGHT, str);

	/* Group name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_LEFTID, str);

	/* User name*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER, str);
	
	/* Phase 1 Algorithms: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_IKE, str);

	/* Phase 2 Algorithms: esp */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_ESP, str);

	/* Domain entry */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_DOMAIN, str);

	//widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_dpd_checkbutton"));
	//if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
	//	nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_DPDTIMEOUT, "0");
	//} else {
		/* If DPD was disabled and now the user wishes to enable it, just
		 * don't pass the DPD_IDLE_TIMEOUT option to openswan and thus use the
		 * default DPD idle time.  Otherwise keep the original DPD idle timeout.
		 */
	//	if (priv->orig_dpd_timeout >= 10) {
	//		char *tmp = g_strdup_printf ("%d", priv->orig_dpd_timeout);
	//		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_DPDTIMEOUT, tmp);
	//		g_free (tmp);
	//	}
	//}

	upw_type = handle_one_pw_type (s_vpn,
	                               priv->builder,
	                               "user_pass_type_combo",
	                               NM_OPENSWAN_XAUTH_PASSWORD,
	                               NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES,
	                               priv->new_connection);
	gpw_type = handle_one_pw_type (s_vpn,
	                               priv->builder,
	                               "group_pass_type_combo",
	                               NM_OPENSWAN_PSK_VALUE,
	                               NM_OPENSWAN_PSK_INPUT_MODES,
	                               priv->new_connection);

	/* User password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (upw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD, str);

	/* Group password */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (gpw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENSWAN_PSK_VALUE, str);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	OpenswanPluginUiWidgetPrivate *priv;
	NMSettingVPN *s_vpn;
	gboolean new = TRUE;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (OPENSWAN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, OPENSWAN_PLUGIN_UI_ERROR, 0, "could not create openswan object");
		return NULL;
	}

	priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();
	g_assert (priv->builder);
	if (gtk_builder_add_from_file (priv->builder, UIDIR "/nm-openswan-dialog.ui", error) == 0) {
		g_object_unref (object);
		return NULL;
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "openswan-vbox"));
	if (!priv->widget) {
		g_set_error (error, OPENSWAN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_plugin_ui (OPENSWAN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpenswanPluginUiWidget *plugin = OPENSWAN_PLUGIN_UI_WIDGET (object);
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (openswan_plugin_ui_widget_parent_class)->dispose (object);
}

static void
openswan_plugin_ui_widget_class_init (OpenswanPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenswanPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
openswan_plugin_ui_widget_init (OpenswanPluginUiWidget *plugin)
{
}

static void
openswan_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, OPENSWAN_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, OPENSWAN_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, OPENSWAN_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openswan_plugin_ui_class_init (OpenswanPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
openswan_plugin_ui_init (OpenswanPluginUi *plugin)
{
}

static void
openswan_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = NULL;
	iface_class->export_to_file = NULL;
	iface_class->get_suggested_name = NULL;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (OPENSWAN_TYPE_PLUGIN_UI, NULL));
}

