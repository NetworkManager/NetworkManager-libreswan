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
#include <glade/glade.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-openswan-service.h"
#include "common-gnome/keyring-helpers.h"
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
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gint orig_dpd_timeout;
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

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str) || strstr (str, " ") || strstr (str, "\t")) {
		g_set_error (error,
		             OPENSWAN_PLUGIN_UI_ERROR,
		             OPENSWAN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSWAN_RIGHT);
		return FALSE;
	}

	widget = glade_xml_get_widget (priv->xml, "group_entry");
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

static gboolean
fill_vpn_passwords (OpenswanPluginUiWidget *self, NMConnection *connection)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean success = FALSE;
	char *password = NULL;
	char *group_password = NULL;

	/* Grab secrets from the connection or the keyring */
	if (connection) {
		NMSettingConnection *s_con;
		NMSettingVPN *s_vpn;
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		const char *tmp;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
		if (s_vpn) {
			tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD);
			if (tmp)
				password = gnome_keyring_memory_strdup (tmp);

			tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_PSK_VALUE);
			if (tmp)
				group_password = gnome_keyring_memory_strdup (tmp);
		}

		nm_setting_get_secret_flags (NM_SETTING (s_vpn), OPENSWAN_USER_PASSWORD, &secret_flags, NULL);
		if (!password && (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
				                            OPENSWAN_USER_PASSWORD,
				                            &password,
				                            NULL);
		}

		secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), OPENSWAN_GROUP_PASSWORD, &secret_flags, NULL);
		if (!group_password && (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED)) {
			keyring_helpers_get_one_secret (nm_setting_connection_get_uuid (s_con),
			                                OPENSWAN_GROUP_PASSWORD,
			                                &group_password,
			                                NULL);
		}
	}

	/* User password */
	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	if (!widget)
		goto out;
	if (password)
		gtk_entry_set_text (GTK_ENTRY (widget), password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Group password */
	widget = glade_xml_get_widget (priv->xml, "group_password_entry");
	if (!widget)
		goto out;
	if (group_password)
		gtk_entry_set_text (GTK_ENTRY (widget), group_password);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	success = TRUE;

out:
	gnome_keyring_memory_free (password);
	gnome_keyring_memory_free (group_password);

	return success;
}

static void
show_toggled_cb (GtkCheckButton *button, OpenswanPluginUiWidget *self)
{
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = glade_xml_get_widget (priv->xml, "group_password_entry");
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
	widget = glade_xml_get_widget (priv->xml, "user_pass_type_combo");
	if (combo == widget)
		entry = "user_password_entry";
	else {
		widget = glade_xml_get_widget (priv->xml, "group_pass_type_combo");
		if (combo == widget)
			entry = "group_password_entry";
	}
	if (!entry)
		return;

	widget = glade_xml_get_widget (priv->xml, entry);
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
	}
	return NM_OPENSWAN_PW_TYPE_SAVE;
}

static void
init_one_pw_combo (OpenswanPluginUiWidget *self,
                   NMSettingVPN *s_vpn,
                   const char *combo_name,
                   const char *key,
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
	widget = glade_xml_get_widget (priv->xml, entry_name);
	if (widget) {
		const char *tmp;

		tmp = gtk_entry_get_text (GTK_ENTRY (widget));
		if (tmp && strlen (tmp))
			default_idx = 0;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	if (s_vpn)
		value = nm_setting_vpn_get_data_item (s_vpn, key);
	if (!value)
		value = secret_flags_to_pw_type (s_vpn, key);

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

	widget = glade_xml_get_widget (priv->xml, combo_name);
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

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_RIGHT);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "group_entry");
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
	fill_vpn_passwords (self, connection);

	init_one_pw_combo (self, s_vpn, "user_pass_type_combo",
	                   NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES, "user_password_entry");
	init_one_pw_combo (self, s_vpn, "group_pass_type_combo",
	                   NM_OPENSWAN_PSK_INPUT_MODES, "group_password_entry");

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 1 Algorithms: IKE*/
	widget = glade_xml_get_widget (priv->xml, "phase1_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_IKE);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Phase 2 Algorithms: ESP*/
	widget = glade_xml_get_widget (priv->xml, "phase2_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_ESP);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, GTK_WIDGET (widget));
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_DOMAIN);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/*widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
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

	widget = glade_xml_get_widget (priv->xml, "show_passwords_checkbutton");
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
handle_one_pw_type (NMSettingVPN *s_vpn, GladeXML *xml, const char *name, const char *key)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	GtkWidget *widget;
	guint32 pw_type;
	const char *data_val = NULL;

	widget = glade_xml_get_widget (xml, name);

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), key, &flags, NULL);
	flags &= ~(NM_SETTING_SECRET_FLAG_NOT_SAVED | NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

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

	nm_setting_vpn_add_data_item (s_vpn, key, data_val);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), key, flags, NULL);
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
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_RIGHT, str);

	/* Group name */
	widget = glade_xml_get_widget (priv->xml, "group_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_LEFTID, str);

	/* User name*/
	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER, str);
	
	/* Phase 1 Algorithms: ike */
	widget = glade_xml_get_widget (priv->xml, "phase1_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_IKE, str);

	/* Phase 2 Algorithms: esp */
	widget = glade_xml_get_widget (priv->xml, "phase2_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_ESP, str);

	/* Domain entry */
	widget = glade_xml_get_widget (priv->xml, "domain_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSWAN_DOMAIN, str);

	//widget = glade_xml_get_widget (priv->xml, "disable_dpd_checkbutton");
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

	upw_type = handle_one_pw_type (s_vpn, priv->xml, "user_pass_type_combo", NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES);
	gpw_type = handle_one_pw_type (s_vpn, priv->xml, "group_pass_type_combo", NM_OPENSWAN_PSK_INPUT_MODES);

	/* User password */
	widget = glade_xml_get_widget (priv->xml, "user_password_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (upw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD, str);

	/* Group password */
	widget = glade_xml_get_widget (priv->xml, "group_password_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str) && (gpw_type != PW_TYPE_UNUSED))
		nm_setting_vpn_add_secret (s_vpn, NM_OPENSWAN_PSK_VALUE, str);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return TRUE;
}

static void
save_one_password (GladeXML *xml,
                   const char *keyring_tag,
                   const char *uuid,
                   const char *id,
                   const char *entry,
                   const char *combo,
                   const char *desc)
{
	GnomeKeyringResult ret;
	GtkWidget *widget;
	const char *password;
	gboolean saved = FALSE;

	widget = glade_xml_get_widget (xml, combo);
	g_assert (widget);
	if (gtk_combo_box_get_active (GTK_COMBO_BOX (widget)) == PW_TYPE_SAVE) {
		widget = glade_xml_get_widget (xml, entry);
		g_assert (widget);
		password = gtk_entry_get_text (GTK_ENTRY (widget));
		if (password && strlen (password)) {
			ret = keyring_helpers_save_secret (uuid, id, NULL, keyring_tag, password);
			if (ret == GNOME_KEYRING_RESULT_OK)
				saved = TRUE;
			else
				g_warning ("%s: failed to save %s to keyring.", __func__, desc);
		}
	}

	if (!saved)
		keyring_helpers_delete_secret (uuid, keyring_tag);
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	OpenswanPluginUiWidget *self = OPENSWAN_PLUGIN_UI_WIDGET (iface);
	OpenswanPluginUiWidgetPrivate *priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	const char *id, *uuid;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_con || !s_vpn) {
		g_set_error (error,
		             OPENSWAN_PLUGIN_UI_ERROR,
		             OPENSWAN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing connection or VPN settings");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENSWAN_XAUTH_PASSWORD, &secret_flags, NULL)) {
		if (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED) {
			save_one_password (priv->xml, OPENSWAN_USER_PASSWORD, uuid, id,
			                   "user_password_entry", "user_pass_type_combo", "user password");
		}
	}

	if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENSWAN_PSK_VALUE, &secret_flags, NULL)) {
		if (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED) {
			save_one_password (priv->xml, OPENSWAN_GROUP_PASSWORD, uuid, id,
			                   "group_password_entry", "group_pass_type_combo", "group password");
		}
	}

	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	OpenswanPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (OPENSWAN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, OPENSWAN_PLUGIN_UI_ERROR, 0, "could not create openswan object");
		return NULL;
	}

	priv = OPENSWAN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openswan-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "openswan-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, OPENSWAN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "openswan-vbox");
	if (!priv->widget) {
		g_set_error (error, OPENSWAN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

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

	if (priv->xml)
		g_object_unref (priv->xml);

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
	iface_class->save_secrets = save_secrets;
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	NMSettingConnection *s_con;
	const char *id, *uuid;

	/* Remove any secrets in the keyring associated with this connection's UUID */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
		             OPENSWAN_PLUGIN_UI_ERROR,
		             OPENSWAN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "missing 'connection' setting");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	if (!keyring_helpers_delete_secret (uuid, OPENSWAN_USER_PASSWORD))
		g_message ("%s: couldn't delete user password for '%s'", __func__, id);

	if (!keyring_helpers_delete_secret (uuid, OPENSWAN_GROUP_PASSWORD))
		g_message ("%s: couldn't delete group password for '%s'", __func__, id);

	return TRUE;
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
	iface_class->delete_connection = delete_connection;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (OPENSWAN_TYPE_PLUGIN_UI, NULL));
}

