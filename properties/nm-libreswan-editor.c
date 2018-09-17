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

#include "nm-libreswan-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>

#define ENC_TYPE_SECURE 0
#define ENC_TYPE_WEAK   1
#define ENC_TYPE_NONE   2

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1
#define PW_TYPE_UNUSED 2

/*****************************************************************************/

static void libreswan_editor_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (LibreswanEditor, libreswan_editor, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               libreswan_editor_interface_init))

#define LIBRESWAN_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), LIBRESWAN_TYPE_EDITOR, LibreswanEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWidget *advanced_dialog;
} LibreswanEditorPrivate;

#define TYPE_IKEV1_XAUTH 0
#define TYPE_IKEV2_CERT  1

/* Define a three-valued logic (3VL) for managing boolean values that allows a third value
 * beside the common "yes"/"no". The third value actual meaning may depend on the context,
 * e.g., for fragmentation it means "force".
 */
#define TYPE_3VL_NO    0
#define TYPE_3VL_YES   1
#define TYPE_3VL_OTHER 2

static gboolean
check_validity (LibreswanEditor *self, GError **error)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	int contype;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_LIBRESWAN_KEY_RIGHT);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "type_combo"));
	contype = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

	if (contype == TYPE_IKEV2_CERT) {
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_LIBRESWAN_KEY_LEFTCERT);
			return FALSE;
		}
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (LIBRESWAN_EDITOR (user_data), "changed");
}

static void
contype_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (user_data);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	int contype;
	const char *ikev1_widgets[] = { "user_label" , "user_entry",
	                                "user_password_label", "user_password_entry",
	                                "group_label", "group_entry",
	                                "group_password_label", "group_password_entry",
	                                "show_passwords_checkbutton",
	                                NULL };
	const char *ikev2_widgets[] = { "cert_label", "cert_entry",
	                                "remoteid_label", "remoteid_entry",
	                                NULL };
	const char **widget_show;
	const char **widget_hide;

	contype = gtk_combo_box_get_active (GTK_COMBO_BOX (combo));

	switch (contype) {
	case TYPE_IKEV1_XAUTH:
		widget_show = ikev1_widgets;
		widget_hide = ikev2_widgets;
		break;
	case TYPE_IKEV2_CERT:
	default:
		widget_show = ikev2_widgets;
		widget_hide = ikev1_widgets;
		break;
	}
	while (*widget_show)
		gtk_widget_show (GTK_WIDGET (gtk_builder_get_object (priv->builder, *widget_show++)));
	while (*widget_hide)
		gtk_widget_hide (GTK_WIDGET (gtk_builder_get_object (priv->builder, *widget_hide++)));

}

static void
setup_password_widget (LibreswanEditor *self,
                       const char *entry_name,
                       NMSettingVpn *s_vpn,
                       const char *secret_name,
                       gboolean new_connection)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *value;

	widget = (GtkWidget *) gtk_builder_get_object (priv->builder, entry_name);
	g_assert (widget);
	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_entry_set_text (GTK_ENTRY (widget), value ? value : "");
	}

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
password_storage_changed_cb (GObject *entry,
                             GParamSpec *pspec,
                             gpointer user_data)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (user_data);

	stuff_changed_cb (NULL, self);
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
init_password_icon (LibreswanEditor *self,
                    NMSettingVpn *s_vpn,
                    const char *secret_key,
                    const char *type_key,
                    const char *entry_name)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *entry;
	const char *value;
	const char *flags = NULL;

	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	g_assert (entry);

	nma_utils_setup_password_storage (entry, 0, (NMSetting *) s_vpn, secret_key,
	                                  TRUE, FALSE);

	/* If there's no password and no flags in the setting,
	 * initialize flags as "always-ask".
	 */
	if (s_vpn) {
		flags = secret_flags_to_pw_type (s_vpn, secret_key);
		if (!flags || !strcmp (flags, NM_LIBRESWAN_PW_TYPE_SAVE))
			flags = nm_setting_vpn_get_data_item (s_vpn, type_key);
	}
	value = gtk_entry_get_text (GTK_ENTRY (entry));
	if ((!value || !*value) && !flags) {
		nma_utils_update_password_storage (entry, NM_SETTING_SECRET_FLAG_NOT_SAVED,
		                                   (NMSetting *) s_vpn, secret_key);
	}

	g_signal_connect (entry, "notify::secondary-icon-name",
	                  G_CALLBACK (password_storage_changed_cb), self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (user_data);
	GtkWidget *toplevel;

	if (gtk_widget_get_visible (priv->advanced_dialog))
		gtk_widget_hide (priv->advanced_dialog);
	else {
		toplevel = gtk_widget_get_toplevel (priv->widget);
		if (gtk_widget_is_toplevel (toplevel))
			gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), GTK_WINDOW (toplevel));
		gtk_widget_show_all (priv->advanced_dialog);
	}
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (iface);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}


/* Init the widget on the basis of its actual type.
 *  widget_name: the name of the widget
 *  key_name:    the name of the key where the config value is stored
 *  match_value: used only for toggle_button and combo_box widgets; when matched
 *               in the former it will set the toggle button as active, in the latter
 *               will be used as a match for enabling the third index of possible values
 *               (a three-valued logic value is expected: "no", "yes" or "match_value").
 */
static gboolean
init_widget (LibreswanEditor *self,
             NMSettingVpn *s_vpn,
             const char *widget_name,
             const char *key_name,
             const char *match_value)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *value = NULL;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, widget_name));
	g_return_val_if_fail (widget, FALSE);

	if (GTK_IS_ENTRY (widget))
		gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, key_name);
		if (value && *value) {
			if (GTK_IS_ENTRY (widget)) {
				gtk_entry_set_text (GTK_ENTRY (widget), value);
			} else if (GTK_IS_CHECK_BUTTON (widget)) {
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget),
				                              nm_streq0 (value, match_value));
			} else if (GTK_IS_COMBO_BOX (widget)) {
				gint idx = -1;

				if (nm_streq (value, "no"))
					idx = TYPE_3VL_NO;
				else if (nm_streq (value, "yes"))
					idx = TYPE_3VL_YES;
				else if (nm_streq0 (value, match_value))
					idx = TYPE_3VL_OTHER;
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), idx);
			}
		}
	}
	g_signal_connect (G_OBJECT (widget),
	                  GTK_IS_CHECK_BUTTON (widget) ? "toggled" : "changed",
	                  G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
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
	gboolean widget_updated;
	int contype = TYPE_IKEV2_CERT;

	s_vpn = nm_connection_get_setting_vpn (connection);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "type_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (!new_connection && s_vpn) {
		const char *ikev2;

		ikev2 = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2);
		if (NM_IN_STRSET (ikev2,
		                  NM_LIBRESWAN_IKEV2_YES,
		                  NM_LIBRESWAN_IKEV2_PROPOSE,
		                  NM_LIBRESWAN_IKEV2_INSIST)) {
			contype = TYPE_IKEV2_CERT;
		} else
			contype = TYPE_IKEV1_XAUTH;
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (contype_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), contype);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Fill the VPN passwords *before* initializing the PW type combos, since
	 * knowing if there are passwords when initializing the combos is helpful.
	 */
	setup_password_widget (self,
	                       "user_password_entry",
	                       s_vpn,
	                       NM_LIBRESWAN_KEY_XAUTH_PASSWORD,
	                       new_connection);
	setup_password_widget (self,
	                       "group_password_entry",
	                       s_vpn,
	                       NM_LIBRESWAN_KEY_PSK_VALUE,
	                       new_connection);

	init_password_icon (self,
	                    s_vpn,
	                    NM_LIBRESWAN_KEY_XAUTH_PASSWORD,
	                    NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES,
	                    "user_password_entry");
	init_password_icon (self,
	                    s_vpn,
	                    NM_LIBRESWAN_KEY_PSK_VALUE,
	                    NM_LIBRESWAN_KEY_PSK_INPUT_MODES,
	                    "group_password_entry");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
	                  (GCallback) show_toggled_cb,
	                  self);

	widget_updated = init_widget (self, s_vpn, "gateway_entry", NM_LIBRESWAN_KEY_RIGHT, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "user_entry", NM_LIBRESWAN_KEY_LEFTXAUTHUSER, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "group_entry", NM_LIBRESWAN_KEY_LEFTID, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "cert_entry", NM_LIBRESWAN_KEY_LEFTCERT, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "remoteid_entry", NM_LIBRESWAN_KEY_RIGHTID, NULL);
	g_return_val_if_fail (widget_updated, FALSE);


	/* Advanced Dialog */
	widget_updated = init_widget (self, s_vpn, "domain_entry", NM_LIBRESWAN_KEY_DOMAIN, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "phase1_entry", NM_LIBRESWAN_KEY_IKE, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "phase2_entry", NM_LIBRESWAN_KEY_ESP, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "phase1_lifetime_entry", NM_LIBRESWAN_KEY_IKELIFETIME, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "phase2_lifetime_entry", NM_LIBRESWAN_KEY_SALIFETIME, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "rekey_checkbutton", NM_LIBRESWAN_KEY_REKEY, "no");
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "remote_network_entry", NM_LIBRESWAN_KEY_REMOTENETWORK, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "narrowing_checkbutton", NM_LIBRESWAN_KEY_NARROWING, "yes");
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "fragmentation_combo", NM_LIBRESWAN_KEY_FRAGMENTATION, "force");
	g_return_val_if_fail (widget_updated, FALSE);

	widget_updated = init_widget (self, s_vpn, "mobike_combo", NM_LIBRESWAN_KEY_MOBIKE, NULL);
	g_return_val_if_fail (widget_updated, FALSE);

	priv->advanced_dialog = GTK_WIDGET (gtk_builder_get_object (priv->builder, "libreswan-advanced-dialog"));
	g_return_val_if_fail (priv->advanced_dialog != NULL, FALSE);

	g_signal_connect (G_OBJECT (priv->advanced_dialog), "delete-event",
	                  G_CALLBACK (gtk_widget_hide_on_delete), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "apply_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static void
save_one_password (NMSettingVpn *s_vpn,
                   GtkBuilder *builder,
                   const char *entry_name,
                   const char *secret_key,
                   const char *type_key)
{
	NMSettingSecretFlags flags;
	const char *data_val = NULL, *password;
	GtkWidget *entry;

	/* Get secret flags */
	entry = GTK_WIDGET (gtk_builder_get_object (builder, entry_name));
	flags = nma_utils_menu_to_secret_flags (entry);

	/* Save password and convert flags to legacy data items */
	switch (flags) {
	case NM_SETTING_SECRET_FLAG_NONE:
	case NM_SETTING_SECRET_FLAG_AGENT_OWNED:
		password = gtk_entry_get_text (GTK_ENTRY (entry));
		if (password && *password)
			nm_setting_vpn_add_secret (s_vpn, secret_key, password);
		data_val = NM_LIBRESWAN_PW_TYPE_SAVE;
		break;
	case NM_SETTING_SECRET_FLAG_NOT_REQUIRED:
		data_val = NM_LIBRESWAN_PW_TYPE_UNUSED;
		break;
	case NM_SETTING_SECRET_FLAG_NOT_SAVED:
	default:
		data_val = NM_LIBRESWAN_PW_TYPE_ASK;
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
	const char *str;
	int contype;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_LIBRESWAN, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "type_combo"));
	contype = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (contype) {
	case TYPE_IKEV2_CERT:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2, NM_LIBRESWAN_IKEV2_INSIST);

		/* Certificate name */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT, str);

		/* Remote ID */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remoteid_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTID, str);

		/* For now just enforce retrieving the local id from the certificate.
		 * We will allow to change this when we will refactore the "advanced"
		 * section and will expose the "leftid" parameter there.
		 */
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID, "%fromcert");

		break;

	case TYPE_IKEV1_XAUTH:
		/* Group name */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID, str);

		/* User name*/
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER, str);

		save_one_password (s_vpn,
		                   priv->builder,
		                   "user_password_entry",
		                   NM_LIBRESWAN_KEY_XAUTH_PASSWORD,
		                   NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES);
		save_one_password (s_vpn,
		                   priv->builder,
		                   "group_password_entry",
		                   NM_LIBRESWAN_KEY_PSK_VALUE,
		                   NM_LIBRESWAN_KEY_PSK_INPUT_MODES);
		break;
	default:
		g_assert_not_reached ();
		break;
	}

	/* Phase 1 Algorithms: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE, str);

	/* Phase 2 Algorithms: esp */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP, str);

	/* Phase 1 Lifetime: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "phase1_lifetime_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKELIFETIME, str);

	/* Phase 2 Lifetime: sa */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "phase2_lifetime_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_SALIFETIME, str);

	/* Domain entry */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DOMAIN, str);

	/* Remote Network */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "remote_network_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REMOTENETWORK, str);

	/* Disable rekeying */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "rekey_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY, "no");

	/* Narrowing */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "narrowing_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_NARROWING, "yes");

	/* MOBIKE */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "mobike_combo"));
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == TYPE_3VL_YES)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_MOBIKE, "yes");

	/* Fragmentation */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fragmentation_combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case TYPE_3VL_NO:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, "no");
		break;
	case TYPE_3VL_OTHER:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, "force");
		break;
	}

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

NMVpnEditor *
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
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not create libreswan object");
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
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0,
		             "could not load required resources at %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "libreswan-vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
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

	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_password_entry"));
	g_signal_handlers_disconnect_by_func (G_OBJECT (widget),
	                                      (GCallback) password_storage_changed_cb,
	                                      plugin);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_password_entry"));
	g_signal_handlers_disconnect_by_func (G_OBJECT (widget),
	                                      (GCallback) password_storage_changed_cb,
	                                      plugin);

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

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-libreswan-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_libreswan (NMVpnEditorPlugin *editor_plugin,
                                 NMConnection *connection,
                                 GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_vpn_editor_new (connection, error);
}
#endif

