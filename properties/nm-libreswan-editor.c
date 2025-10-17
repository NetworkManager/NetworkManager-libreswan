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

#include "utils.h"

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

#if !GTK_CHECK_VERSION(4,0,0)
#define gtk_editable_set_text(editable,text)		gtk_entry_set_text(GTK_ENTRY(editable), (text))
#define gtk_editable_get_text(editable)			gtk_entry_get_text(GTK_ENTRY(editable))
#define gtk_check_button_get_active(button)		gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button))
#define gtk_check_button_set_active(button, active)	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), active)
#define gtk_widget_get_root(widget)			gtk_widget_get_toplevel(widget)
#define gtk_window_set_hide_on_close(window, hide)						\
	G_STMT_START {										\
		G_STATIC_ASSERT(hide);								\
		g_signal_connect_swapped (G_OBJECT (window), "delete-event",			\
		                          G_CALLBACK (gtk_widget_hide_on_delete), window); 	\
	} G_STMT_END
#endif

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
	GtkWidget *apply_button;
	NMSettingVpn *s_vpn;
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
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
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
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
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

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, secret_name);
		gtk_editable_set_text (GTK_EDITABLE (widget), value ? value : "");
	}

	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb), self);
}

static void
show_toggled_cb (GtkCheckButton *button, LibreswanEditor *self)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_check_button_get_active (GTK_CHECK_BUTTON (button));

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
	value = gtk_editable_get_text (GTK_EDITABLE (entry));
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
        void *root;

	root = gtk_widget_get_root (priv->widget);
	if (GTK_IS_WINDOW(root))
		gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), GTK_WINDOW (root));
	gtk_widget_show (priv->advanced_dialog);
}

static void update_adv_settings (LibreswanEditor *self, NMSettingVpn *s_vpn);
static void populate_adv_dialog (LibreswanEditor *self);

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (user_data);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);

	gtk_widget_hide (priv->advanced_dialog);
	gtk_window_set_transient_for (GTK_WINDOW (priv->advanced_dialog), NULL);

	if (response == GTK_RESPONSE_APPLY)
		update_adv_settings (self, priv->s_vpn);
	else
		populate_adv_dialog (self);
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (iface);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
insert_text_check (GtkEditable *editable, char *new_text,
                   int len, int *pos, gpointer user_data)
{
	nm_auto_free_gstring GString *new_val = NULL;
	const char *key = user_data;
	const char *val;

	val = gtk_editable_get_text (editable);
	if (*val == '\0')
		return;

	new_val = g_string_new (gtk_editable_get_text (editable));
	g_string_insert_len (new_val, *pos, new_text, len);
	if (!nm_libreswan_check_value (key, new_val->str, NULL))
		g_signal_stop_emission_by_name (G_OBJECT (editable), "insert-text");
}

static void
populate_widget (LibreswanEditor *self,
                 const char *widget_name,
                 const char *key_name,
                 const char *alt_key_name,
                 const char *match_value,
                 GCallback changed_cb,
                 gpointer user_data)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *value = NULL;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, widget_name));
	g_return_if_fail (widget);

	if (priv->s_vpn) {
		value = nm_setting_vpn_get_data_item (priv->s_vpn, key_name);
		if (!value && alt_key_name)
			value = nm_setting_vpn_get_data_item (priv->s_vpn, alt_key_name);
	}

	if (!value)
		value = "";

	if (GTK_IS_ENTRY (widget)) {
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		g_signal_connect (G_OBJECT (widget),
		                  "insert-text",
		                  G_CALLBACK (insert_text_check),
		                  (gpointer) key_name);

	} else if (GTK_IS_CHECK_BUTTON (widget)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget),
					     nm_streq0 (value, match_value));
	} else if (GTK_IS_COMBO_BOX (widget)) {
		gint idx = -1;

		if (nm_streq (widget_name, "dpd_action_combo")) {
			idx = 0;
			if (nm_streq (value, "hold"))
				idx = 1;
			else if (nm_streq (value, "clear"))
				idx = 2;
			else if (nm_streq (value, "restart"))
				idx = 3;
		} else {
			if (nm_streq (value, "no"))
				idx = TYPE_3VL_NO;
			else if (nm_streq (value, "yes"))
				idx = TYPE_3VL_YES;
			else if (nm_streq0 (value, match_value))
				idx = TYPE_3VL_OTHER;
		}
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), idx);
	}

	g_signal_connect (G_OBJECT (widget),
	                  GTK_IS_CHECK_BUTTON (widget) ? "toggled" : "changed",
	                  G_CALLBACK (changed_cb), user_data);
}

static gboolean
check_adv_validity (LibreswanEditor *self, GError **error)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_network_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (!nm_libreswan_parse_subnets (str, NULL, error))
		return FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_network_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (!nm_libreswan_parse_subnets (str, NULL, error))
		return FALSE;

	return TRUE;
}

static void
adv_changed_cb (GtkWidget *widget, gpointer user_data)
{
	LibreswanEditor *self = LIBRESWAN_EDITOR (user_data);
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;
	gboolean settings_valid;

	settings_valid = check_adv_validity (self, &error);
	gtk_widget_set_sensitive (priv->apply_button, settings_valid);
	gtk_widget_set_tooltip_text (priv->apply_button,
	                             settings_valid ? NULL : error->message);
}

static inline void
populate_adv (LibreswanEditor *self,
               const char *widget_name,
               const char *key_name,
               const char *alt_key_name,
               const char *match_value)
{
	populate_widget (self,
			 widget_name,
			 key_name,
			 alt_key_name,
			 match_value,
			 G_CALLBACK (adv_changed_cb),
			 self);
}

static void
populate_adv_dialog (LibreswanEditor *self)
{
	populate_adv (self, "domain_entry", NM_LIBRESWAN_KEY_DOMAIN, NULL, NULL);
	populate_adv (self, "phase1_entry", NM_LIBRESWAN_KEY_IKE, NULL, NULL);
	populate_adv (self, "phase2_entry", NM_LIBRESWAN_KEY_ESP, NULL, NULL);
	populate_adv (self, "phase1_lifetime_entry", NM_LIBRESWAN_KEY_IKELIFETIME, NULL, NULL);
	populate_adv (self, "phase2_lifetime_entry", NM_LIBRESWAN_KEY_SALIFETIME, NULL, NULL);
	populate_adv (self, "rekey_checkbutton", NM_LIBRESWAN_KEY_REKEY, NULL, "no");
	populate_adv (self, "pfs_checkbutton", NM_LIBRESWAN_KEY_PFS, NULL, "no");
	populate_adv (self, "local_network_entry", NM_LIBRESWAN_KEY_LEFTSUBNETS, NM_LIBRESWAN_KEY_LEFTSUBNET, NULL);
	populate_adv (self, "remote_network_entry", NM_LIBRESWAN_KEY_RIGHTSUBNETS, NM_LIBRESWAN_KEY_RIGHTSUBNET, NULL);
	populate_adv (self, "narrowing_checkbutton", NM_LIBRESWAN_KEY_NARROWING, NULL, "yes");
	populate_adv (self, "fragmentation_combo", NM_LIBRESWAN_KEY_FRAGMENTATION, NULL, "force");
	populate_adv (self, "mobike_combo", NM_LIBRESWAN_KEY_MOBIKE, NULL, NULL);
	populate_adv (self, "dpd_delay_entry", NM_LIBRESWAN_KEY_DPDDELAY, NULL, NULL);
	populate_adv (self, "dpd_timeout_entry", NM_LIBRESWAN_KEY_DPDTIMEOUT, NULL, NULL);
	populate_adv (self, "dpd_action_combo", NM_LIBRESWAN_KEY_DPDACTION, NULL, NULL);
	populate_adv (self, "ipsec_interface_entry", NM_LIBRESWAN_KEY_IPSEC_INTERFACE, NULL, NULL);
	populate_adv (self, "authby_entry", NM_LIBRESWAN_KEY_AUTHBY, NULL, NULL);
	populate_adv (self, "disable_modecfgclient_checkbutton", NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT, NULL, "no");
	populate_adv (self, "remote_cert_entry", NM_LIBRESWAN_KEY_RIGHTCERT, NULL, NULL);
	populate_adv (self, "require_id_on_certificate_checkbutton", NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE, NULL, "no");
	populate_adv (self, "leftsendcert_entry", NM_LIBRESWAN_KEY_LEFTSENDCERT, NULL, NULL);
	populate_adv (self, "rightca", NM_LIBRESWAN_KEY_RIGHTCA, NULL, NULL);
	adv_changed_cb (NULL, self);
}

static inline void
populate_main (LibreswanEditor *self,
               const char *widget_name,
               const char *key_name,
               const char *alt_key_name,
               const char *match_value)
{
	populate_widget (self,
			 widget_name,
			 key_name,
			 alt_key_name,
			 match_value,
			 G_CALLBACK (stuff_changed_cb),
			 self);
}

static gboolean
init_editor_plugin (LibreswanEditor *self,
                    NMConnection *connection,
                    gboolean new_connection,
                    GError **error)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = NULL;
	gs_unref_object NMSettingVpn *s_vpn_sanitized = NULL;
	GtkWidget *widget;
	int contype = TYPE_IKEV2_CERT;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn) {
		/* Here it is possible to have an empty VPN setting (i.e. new connection).
		 * If we have one, try to sanitize. If we don't, or sanitize fails, just
		 * continue as with an empty setting. */
		s_vpn_sanitized = sanitize_setting_vpn (s_vpn, NULL);
		if (s_vpn_sanitized)
			s_vpn = s_vpn_sanitized;
	}

	if (s_vpn)
		priv->s_vpn = NM_SETTING_VPN (nm_setting_duplicate (NM_SETTING (s_vpn)));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "type_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);
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

	populate_main (self, "gateway_entry", NM_LIBRESWAN_KEY_RIGHT, NULL, NULL);
	populate_main (self, "user_entry", NM_LIBRESWAN_KEY_LEFTXAUTHUSER, NM_LIBRESWAN_KEY_LEFTUSERNAME, NULL);
	populate_main (self, "group_entry", NM_LIBRESWAN_KEY_LEFTID, NULL, NULL);
	populate_main (self, "cert_entry", NM_LIBRESWAN_KEY_LEFTCERT, NULL, NULL);
	populate_main (self, "remoteid_entry", NM_LIBRESWAN_KEY_RIGHTID, NULL, NULL);

	priv->advanced_dialog = GTK_WIDGET (gtk_builder_get_object (priv->builder, "libreswan-advanced-dialog"));
	g_return_val_if_fail (priv->advanced_dialog != NULL, FALSE);

	gtk_window_set_hide_on_close (GTK_WINDOW (priv->advanced_dialog), TRUE);

	g_signal_connect (G_OBJECT (priv->advanced_dialog), "response",
	                  G_CALLBACK (advanced_dialog_response_cb), self);

	priv->apply_button = GTK_WIDGET (gtk_builder_get_object (priv->builder, "apply_button"));
	g_return_val_if_fail (priv->apply_button != NULL, FALSE);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	populate_adv_dialog (self);

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
		password = gtk_editable_get_text (GTK_EDITABLE (entry));
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

static void
update_adv_settings (LibreswanEditor *self, NMSettingVpn *s_vpn)
{
	LibreswanEditorPrivate *priv = LIBRESWAN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	char *subnets;

	/* Domain entry */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "domain_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DOMAIN, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_DOMAIN);

	/* Local Network(s) */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "local_network_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	subnets = nm_libreswan_normalize_subnets (str, NULL);
	if (subnets == NULL || subnets[0] == '\0') {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNETS);
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNET);
	} else if (strchr (subnets, ',')) {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNET);
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNETS, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNETS);
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSUBNET, str);
	}
	g_free (subnets);

	/* Remote Network(s) */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "remote_network_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	subnets = nm_libreswan_normalize_subnets (str, NULL);
	if (subnets == NULL || subnets[0] == '\0') {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNETS);
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNET);
	} else if (strchr (subnets, ',')) {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNET);
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNETS, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNETS);
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTSUBNET, str);
	}
	g_free (subnets);

	/* Disable rekeying */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "rekey_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY, "no");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_REKEY);

	/* Disable PFS */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "pfs_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_PFS, "no");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_PFS);

	/* Narrowing */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "narrowing_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_NARROWING, "yes");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_NARROWING);

	/* MOBIKE */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "mobike_combo"));
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == TYPE_3VL_YES)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_MOBIKE, "yes");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_MOBIKE);

	/* Fragmentation */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "fragmentation_combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case TYPE_3VL_NO:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, "no");
		break;
	case TYPE_3VL_OTHER:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION, "force");
		break;
	default:
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_FRAGMENTATION);
	}

	/* DPD delay */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dpd_delay_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDDELAY, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDDELAY);

	/* DPD timeout */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dpd_timeout_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDTIMEOUT, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDTIMEOUT);

	/* DPD action */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "dpd_action_combo"));
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (widget))) {
	case 1:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDACTION, "hold");
		break;
	case 2:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDACTION, "clear");
		break;
	case 3:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDACTION, "restart");
		break;
	default:
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_DPDACTION);
	}

	/* IPsec interface */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipsec_interface_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IPSEC_INTERFACE, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_IPSEC_INTERFACE);

	/* Authby */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "authby_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_AUTHBY, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_AUTHBY);

	/* Disable Mode Config client */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "disable_modecfgclient_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT, "no");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT);

	/* Remote certificate */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_cert_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT);

	/* Disable Require ID on certificate */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "require_id_on_certificate_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE, "no");
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE);

	/* leftsendcert */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "leftsendcert_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSENDCERT, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTSENDCERT);

	/* rightca */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "rightca_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCA, str);
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCA);

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
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT, str);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "type_combo"));
	contype = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (contype) {
	case TYPE_IKEV2_CERT:
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKEV2, NM_LIBRESWAN_IKEV2_INSIST);

		/* Certificate name */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "cert_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT, str);

		/* For now just enforce retrieving the local id from the certificate.
		 * We will allow to change this when we will refactore the "advanced"
		 * section and will expose the "leftid" parameter there.
		 */
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID, "%fromcert");

		break;

	case TYPE_IKEV1_XAUTH:
		/* Group name */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "group_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID, str);

		/* User name*/
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTXAUTHUSER);
		nm_setting_vpn_remove_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTUSERNAME);
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "user_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
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

	/* Remote ID */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remoteid_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTID, str);

	/* Phase 1 Algorithms: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase1_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKE, str);

	/* Phase 2 Algorithms: esp */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "phase2_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_ESP, str);

	/* Phase 1 Lifetime: ike */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "phase1_lifetime_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_IKELIFETIME, str);

	/* Phase 2 Lifetime: sa */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder,
	                                             "phase2_lifetime_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_LIBRESWAN_KEY_SALIFETIME, str);

	/* Advanced dialog */
	update_adv_settings (self, s_vpn);

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

	priv->builder = gtk_builder_new ();
	g_assert (priv->builder);

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-libreswan/nm-libreswan-dialog.ui", error)) {
		g_warning ("Couldn't load builder file: %s", error && *error ? (*error)->message : "(unknown)");
		g_object_unref (object);
		return NULL;
	}

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

	g_clear_object (&priv->widget);
	g_clear_object (&priv->builder);
	g_clear_object (&priv->s_vpn);

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

#include "nm-libreswan-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_libreswan (NMVpnEditorPlugin *editor_plugin,
                                 NMConnection *connection,
                                 GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_vpn_editor_new (connection, error);
}
