/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Avesh Agarwal <avagarwa@redhat.com>
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
 * (C) Copyright 2004 - 2011 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-vpn-plugin-utils.h>

#include "src/nm-openswan-service.h"
#include "vpn-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GList *found_list = NULL;
	GnomeKeyringResult ret;
	GnomeKeyringFound *found;
	char *secret = NULL;

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found_list,
	                                      KEYRING_UUID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      uuid,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if (ret == GNOME_KEYRING_RESULT_OK && found_list) {
		found = g_list_nth_data (found_list, 0);
		secret = gnome_keyring_memory_strdup (found->secret);
	}

	gnome_keyring_found_list_free (found_list);
	return secret;
}

static void
keyfile_add_entry_info (GKeyFile    *keyfile,
                        const gchar *key,
                        const gchar *value,
                        const gchar *label,
                        gboolean     is_secret,
                        gboolean     should_ask)
{
	g_key_file_set_string (keyfile, key, "Value", value);
	g_key_file_set_string (keyfile, key, "Label", label);
	g_key_file_set_boolean (keyfile, key, "IsSecret", is_secret);
	g_key_file_set_boolean (keyfile, key, "ShouldAsk", should_ask);
}

static void
keyfile_print_stdout (GKeyFile *keyfile)
{
	gchar *data;
	gsize length;

	data = g_key_file_to_data (keyfile, &length, NULL);

	fputs (data, stdout);

	g_free (data);
}

#if !GLIB_CHECK_VERSION(2,32,0)
#define g_key_file_unref g_key_file_free
#endif

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             gboolean allow_interaction,
             gboolean external_ui_mode,
             const char *in_upw,
             char **out_upw,
             NMSettingSecretFlags upw_flags,
             const char *in_gpw,
             char **out_gpw,
             NMSettingSecretFlags gpw_flags)
{
	VpnPasswordDialog *dialog;
	char *upw = NULL, *gpw = NULL;
	char *prompt;
	gboolean success = FALSE;
	gboolean need_upw = TRUE, need_gpw = TRUE;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (out_upw != NULL, FALSE);
	g_return_val_if_fail (*out_upw == NULL, FALSE);
	g_return_val_if_fail (out_gpw != NULL, FALSE);
	g_return_val_if_fail (*out_gpw == NULL, FALSE);

	if (   !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_upw)
			upw = gnome_keyring_memory_strdup (in_upw);
		else
			upw = keyring_lookup_secret (vpn_uuid, NM_OPENSWAN_XAUTH_PASSWORD);

		/* Try the old name */
		if (upw == NULL)
			upw = keyring_lookup_secret (vpn_uuid, "password");
	}

	if (   !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_gpw)
			gpw = gnome_keyring_memory_strdup (in_gpw);
		else
			gpw = keyring_lookup_secret (vpn_uuid, NM_OPENSWAN_PSK_VALUE);

		/* Try the old name */
		if (gpw == NULL)
			gpw = keyring_lookup_secret (vpn_uuid, "group-password");
	}

	if (!retry) {
		/* Don't ask if both passwords are either saved and present, or unused */
		if (upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			need_upw = FALSE;
		else if (upw && !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_upw = upw;
			need_upw = FALSE;
		}

		if (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			need_gpw = FALSE;
		else if (gpw && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_gpw = gpw;
			need_gpw = FALSE;
		}

		if (!need_upw && !need_gpw)
			return TRUE;
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);

	if (external_ui_mode) {
		GKeyFile *keyfile;

		keyfile = g_key_file_new ();

		g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", _("Authenticate VPN"));

		if (need_upw)
			keyfile_add_entry_info (keyfile, NM_OPENSWAN_XAUTH_PASSWORD, upw ? upw : "", _("Password:"), TRUE, allow_interaction);
		if (need_gpw)
			keyfile_add_entry_info (keyfile, NM_OPENSWAN_PSK_VALUE, gpw ? gpw : "", _("Group Password:"), TRUE, allow_interaction);

		keyfile_print_stdout (keyfile);
		g_key_file_unref (keyfile);

		success = TRUE;
		goto out;
	} else if (allow_interaction == FALSE ||
			   ((upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
				&& (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))) {
		/* If interaction isn't allowed, just return existing secrets
		 * Also, don't ask if both passwords are unused */

		*out_upw = upw;
		*out_gpw = gpw;
		g_free (prompt);
		return TRUE;
	}

	dialog = VPN_PASSWORD_DIALOG (vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));

	vpn_password_dialog_set_password_secondary_label (dialog, _("_Group Password:"));

	/* Don't show the user password entry if the user password isn't required,
	 * or if we don't need new secrets and the user password is saved.
	 */
	if (upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		vpn_password_dialog_set_show_password (dialog, FALSE);
	else if (!retry && upw && !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		vpn_password_dialog_set_show_password (dialog, FALSE);

	if (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		vpn_password_dialog_set_show_password_secondary (dialog, FALSE);
	else if (!retry && gpw && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		vpn_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* On reprompt the first entry of type 'ask' gets the focus */
	if (retry) {
		if (upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			vpn_password_dialog_focus_password (dialog);
		else if (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
			vpn_password_dialog_focus_password_secondary (dialog);
	}

	/* if retrying, pre-fill dialog with the password */
	if (upw)
		vpn_password_dialog_set_password (dialog, upw);

	if (gpw)
		vpn_password_dialog_set_password_secondary (dialog, gpw);

	gtk_widget_show (GTK_WIDGET (dialog));

	/* Show the dialog */
	success = vpn_password_dialog_run_and_block (dialog);
	if (success) {
		*out_upw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password (dialog));
		*out_gpw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password_secondary (dialog));
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

 out:
	g_free (prompt);

	gnome_keyring_memory_free (upw);
	gnome_keyring_memory_free (gpw);

	return success;
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

static NMSettingSecretFlags
get_pw_flags (GHashTable *hash, const char *secret_name, const char *mode_name)
{
	const char *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	/* Try new flags value first */
	if (nm_vpn_plugin_utils_get_secret_flags (hash, secret_name, &flags))
		return flags;

	/* Otherwise try old "password type" value */
	val = g_hash_table_lookup (hash, mode_name);
	if (val) {
		if (g_strcmp0 (val, NM_OPENSWAN_PW_TYPE_ASK) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_SAVED;
		else if (g_strcmp0 (val, NM_OPENSWAN_PW_TYPE_UNUSED) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_REQUIRED;

		/* NM_OPENSWAN_PW_TYPE_SAVE means FLAG_NONE */
	}

	return NM_SETTING_SECRET_FLAG_NONE;
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE, external_ui_mode = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	char *password = NULL, *group_password = NULL;
	NMSettingSecretFlags upw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags gpw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GError *error = NULL;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	gtk_init (&argc, &argv);
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- openswan auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "Error parsing options: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_service == NULL) {
		fprintf (stderr, "A connection UUID and VPN plugin service name are required.\n");
		return 1;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_OPENSWAN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_OPENSWAN);
		return 1;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	upw_flags = get_pw_flags (data, NM_OPENSWAN_XAUTH_PASSWORD, NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES);
	gpw_flags = get_pw_flags (data, NM_OPENSWAN_PSK_VALUE, NM_OPENSWAN_PSK_INPUT_MODES);

	if (!get_secrets (vpn_uuid, vpn_name, retry,
	                  allow_interaction, external_ui_mode,
	                  g_hash_table_lookup (secrets, NM_OPENSWAN_XAUTH_PASSWORD),
	                  &password,
	                  upw_flags,
	                  g_hash_table_lookup (secrets, NM_OPENSWAN_PSK_VALUE),
	                  &group_password,
	                  gpw_flags))
		return 1;

	if (!external_ui_mode) {
		/* dump the passwords to stdout */
		if (password)
			printf ("%s\n%s\n", NM_OPENSWAN_XAUTH_PASSWORD, password);
		if (group_password)
			printf ("%s\n%s\n", NM_OPENSWAN_PSK_VALUE, group_password);
		printf ("\n\n");

		gnome_keyring_memory_free (password);
		gnome_keyring_memory_free (group_password);

		/* for good measure, flush stdout since Kansas is going Bye-Bye */
		fflush (stdout);

		/* Wait for quit signal */
		wait_for_quit ();
	}

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
