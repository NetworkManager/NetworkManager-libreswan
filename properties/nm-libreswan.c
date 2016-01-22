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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <gtk/gtk.h>

#ifdef NM_LIBRESWAN_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#define LIBRESWAN_EDITOR_PLUGIN_ERROR                  NM_SETTING_VPN_ERROR
#define LIBRESWAN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_SETTING_VPN_ERROR_INVALID_PROPERTY

#else /* !NM_LIBRESWAN_OLD */

#include <NetworkManager.h>

#define LIBRESWAN_EDITOR_PLUGIN_ERROR                  NM_CONNECTION_ERROR
#define LIBRESWAN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY
#endif

#include "nm-libreswan-service.h"
#include "nm-libreswan.h"
#include "utils.h"

#define LIBRESWAN_PLUGIN_NAME    _("IPsec based VPN")
#define LIBRESWAN_PLUGIN_DESC    _("IPsec, IKEv1, IKEv2 based VPN")

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1
#define PW_TYPE_UNUSED 2

/************** plugin class **************/

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

/************** UI widget class **************/

static void libreswan_editor_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (LibreswanEditor, libreswan_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               libreswan_editor_interface_init))

#define LIBRESWAN_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), LIBRESWAN_TYPE_EDITOR, LibreswanEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gboolean openswan;
} LibreswanEditorPrivate;


static gboolean
check_validity (LibreswanEditor *self, GError **error)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             LIBRESWAN_EDITOR_PLUGIN_ERROR,
		             LIBRESWAN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_LIBRESWAN_RIGHT);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             LIBRESWAN_EDITOR_PLUGIN_ERROR,
		             LIBRESWAN_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_LIBRESWAN_LEFTID);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (LIBRESWAN_EDITOR (user_data), "changed");
}

static void
setup_password_widget (LibreswanEditor *self,
                       const char *entry_name,
                       NMSettingVpn *s_vpn,
                       const char *secret_name,
                       gboolean new_connection)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	GtkWidget *widget;
	const char *value;

	if (new_connection)
		secret_flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;

	widget = (GtkWidget *) gtk_builder_get_object (priv->builder, entry_name);
	g_assert (widget);
	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_name, &secret_flags, NULL);
	}
	secret_flags &= ~(NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
	g_object_set_data (G_OBJECT (widget), "flags", GUINT_TO_POINTER (secret_flags));

	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb), self);
}

static void
show_toggled_cb (GtkCheckButton *button, LibreswanEditor *self)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
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
pw_type_changed_helper (LibreswanEditor *self, GtkWidget *combo)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
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
	LibreswanEditor *self = LIBRESWAN_EDITOR (user_data);

	pw_type_changed_helper (self, combo);
	stuff_changed_cb (combo, self);
}

static const char *
secret_flags_to_pw_type (NMSettingVpn *s_vpn, const char *key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), key, &flags, NULL)) {
		if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			return NM_LIBRESWAN_PW_TYPE_UNUSED;
		if (flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			return NM_LIBRESWAN_PW_TYPE_ASK;
		return NM_LIBRESWAN_PW_TYPE_SAVE;
	}
	return NULL;
}

static void
init_one_pw_combo (LibreswanEditor *self,
                   NMSettingVpn *s_vpn,
                   const char *combo_name,
                   const char *secret_key,
                   const char *type_key,
                   const char *entry_name)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
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
		if (!strcmp (value, NM_LIBRESWAN_PW_TYPE_SAVE))
			active = 0;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_LIBRESWAN_PW_TYPE_ASK))
			active = 1;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
	if ((active < 0) && value) {
		if (!strcmp (value, NM_LIBRESWAN_PW_TYPE_UNUSED))
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
init_editor_plugin (LibreswanEditor *self,
                    NMConnection *connection,
                    gboolean new_connection,
                    GError **error)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = NULL;
	GtkWidget *widget;
	const char *value = NULL;

	s_vpn = nm_connection_get_setting_vpn (connection);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_RIGHT);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTID);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Fill the VPN passwords *before* initializing the PW type combos, since
	 * knowing if there are passwords when initializing the combos is helpful.
	 */
	setup_password_widget (self,
	                       "user_password_entry",
	                       s_vpn,
	                       NM_LIBRESWAN_XAUTH_PASSWORD,
	                       new_connection);
	setup_password_widget (self,
	                       "group_password_entry",
	                       s_vpn,
	                       NM_LIBRESWAN_PSK_VALUE,
	                       new_connection);

	init_one_pw_combo (self,
	                   s_vpn,
	                   "user_pass_type_combo",
	                   NM_LIBRESWAN_XAUTH_PASSWORD,
	                   NM_LIBRESWAN_XAUTH_PASSWORD_INPUT_MODES,
	                   "user_password_entry");
	init_one_pw_combo (self,
	                   s_vpn,
	                   "group_pass_type_combo",
	                   NM_LIBRESWAN_PSK_VALUE,
	                   NM_LIBRESWAN_PSK_INPUT_MODES,
	                   "group_password_entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 1 Algorithms: IKE*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_IKE);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 2 Algorithms: ESP*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_ESP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	if (s_vpn) {
		const char *type = nm_setting_vpn_get_service_type (s_vpn);
		priv->openswan = (g_strcmp0 (type, NM_VPN_SERVICE_TYPE_OPENSWAN) == 0);
	}

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (iface);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
save_one_password (NMSettingVpn *s_vpn,
                   GtkBuilder *builder,
                   const char *entry_name,
                   const char *combo_name,
                   const char *secret_key,
                   const char *type_key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	const char *data_val = NULL, *password;
	GtkWidget *entry, *combo;

	entry = GTK_WIDGET (gtk_builder_get_object (builder, entry_name));
	flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (entry), "flags"));

	combo = GTK_WIDGET (gtk_builder_get_object (builder, combo_name));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_SAVE:
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (password && strlen (password))
			nm_setting_vpn_add_secret (s_vpn, secret_key, password);
		data_val = NM_LIBRESWAN_PW_TYPE_SAVE;
		break;
	case PW_TYPE_UNUSED:
		data_val = NM_LIBRESWAN_PW_TYPE_UNUSED;
		flags |= NM_SETTING_SECRET_FLAG_NOT_REQUIRED;
		break;
	case PW_TYPE_ASK:
	default:
		data_val = NM_LIBRESWAN_PW_TYPE_ASK;
		flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
		break;
	}

	/* Set both new secret flags and old data item for backwards compat */
	nm_setting_vpn_add_data_item (s_vpn, type_key, data_val);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), secret_key, flags, NULL);
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (iface);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	char *str;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_RIGHT, str);

	/* Group name */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTID, str);

	/* User name*/
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_LEFTXAUTHUSER, str);
	
	/* Phase 1 Algorithms: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_IKE, str);

	/* Phase 2 Algorithms: esp */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_ESP, str);

	/* Domain entry */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_DOMAIN, str);

	save_one_password (s_vpn,
	                   priv->builder,
	                   "user_password_entry",
	                   "user_pass_type_combo",
	                   NM_LIBRESWAN_XAUTH_PASSWORD,
	                   NM_LIBRESWAN_XAUTH_PASSWORD_INPUT_MODES);
	save_one_password (s_vpn,
	                   priv->builder,
	                   "group_password_entry",
	                   "group_pass_type_combo",
	                   NM_LIBRESWAN_PSK_VALUE,
	                   NM_LIBRESWAN_PSK_INPUT_MODES);

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

static NMVpnEditor *
nm_vpn_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	LibreswanEditorPrivate *priv;
	char *ui_file;
	NMSettingVpn *s_vpn;
	gboolean is_new = TRUE;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (LIBRESWAN_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error (error, LIBRESWAN_EDITOR_PLUGIN_ERROR, 0, "could not create libreswan object");
		return NULL;
	}

	priv = LIBRESWAN_EDITOR_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-libreswan-dialog.ui");
	priv->builder = gtk_builder_new ();
	g_assert (priv->builder);

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, LIBRESWAN_EDITOR_PLUGIN_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "libreswan-vbox"));
	if (!priv->widget) {
		g_set_error (error, LIBRESWAN_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &is_new);

	if (!init_editor_plugin (LIBRESWAN_EDITOR (object), connection, is_new, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	LibreswanEditor *plugin = LIBRESWAN_EDITOR (object);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	G_OBJECT_CLASS (libreswan_editor_parent_class)->dispose (object);
}

static void
libreswan_editor_class_init (LibreswanEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (LibreswanEditorPrivate));

	object_class->dispose = dispose;
}

static void
libreswan_editor_init (LibreswanEditor *plugin)
{
}

static void
libreswan_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static NMConnection *
import_from_file (NMVpnEditorPlugin *self,
                  const char *path,
                  GError **error)
{
	NMConnection *connection;
	int fd;

	fd = g_open (path, O_RDONLY, 0777);
	if (fd == -1) {
		g_set_error (error, LIBRESWAN_EDITOR_PLUGIN_ERROR, 0,
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
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	int fd;

	fd = g_open (path, O_WRONLY | O_CREAT, 0777);
	if (fd == -1) {
		g_set_error (error, LIBRESWAN_EDITOR_PLUGIN_ERROR, 0,
		             _("Can't open file '%s': %s"), path, g_strerror (errno));
		return FALSE;
	}

	nm_libreswan_config_write (fd, connection, NULL, priv->openswan);

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

