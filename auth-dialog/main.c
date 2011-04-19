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

#include "common-gnome/keyring-helpers.h"
#include "src/nm-openswan-service.h"
#include "gnome-two-password-dialog.h"

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             gboolean allow_interaction,
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
			keyring_helpers_get_one_secret (vpn_uuid, OPENSWAN_USER_PASSWORD, &upw);
	}

	if (   !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_gpw)
			gpw = gnome_keyring_memory_strdup (in_gpw);
		else
			keyring_helpers_get_one_secret (vpn_uuid, OPENSWAN_GROUP_PASSWORD, &gpw);
	}

	if (!retry) {
		gboolean need_upw = TRUE, need_gpw = TRUE;

		/* Don't ask if both passwords are either saved and present, or unused */
		if (upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			need_upw = FALSE;
		else if (upw && !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			need_upw = FALSE;

		if (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
			need_gpw = FALSE;
		else if (gpw && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			need_gpw = FALSE;

		if (!need_upw && !need_gpw)
			return TRUE;
	} else {
		/* Don't ask if both passwords are unused */
		if (   (upw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		    && (gpw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			return TRUE;
	}

	/* If interaction isn't allowed, just return existing secrets */
	if (allow_interaction == FALSE) {
		*out_upw = upw;
		*out_gpw = gpw;
		return TRUE;
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = VPN_PASSWORD_DIALOG (vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));
	g_free (prompt);

	vpn_password_dialog_set_show_remember (dialog, FALSE);
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
	if (upw) {
		vpn_password_dialog_set_password (dialog, upw);
		memset (upw, 0, strlen (upw));
		gnome_keyring_memory_free (upw);
	}
	if (gpw) {
		vpn_password_dialog_set_password_secondary (dialog, gpw);
		memset (gpw, 0, strlen (gpw));
		gnome_keyring_memory_free (gpw);
	}

	gtk_widget_show (GTK_WIDGET (dialog));

	/* Show the dialog */
	success = vpn_password_dialog_run_and_block (dialog);
	if (success) {
		*out_upw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password (dialog));
		*out_gpw = gnome_keyring_memory_strdup (vpn_password_dialog_get_password_secondary (dialog));

		if (upw_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED) {
		    if (*out_upw && !(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
				keyring_helpers_save_secret (vpn_uuid, vpn_name, NULL, OPENSWAN_USER_PASSWORD, *out_upw);
			else {
				/* Clear the password from the keyring */
				keyring_helpers_delete_secret (vpn_uuid, OPENSWAN_USER_PASSWORD);
			}
		}

		if (gpw_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED) {
		    if (*out_gpw && !(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
				keyring_helpers_save_secret (vpn_uuid, vpn_name, NULL, OPENSWAN_GROUP_PASSWORD, *out_gpw);
			else {
				/* Clear the password from the keyring */
				keyring_helpers_delete_secret (vpn_uuid, OPENSWAN_GROUP_PASSWORD);
			}
		}
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

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
	gboolean retry = FALSE, allow_interaction = FALSE;
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
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	gtk_init (&argc, &argv);
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- openswan auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_warning ("Error parsing options: %s\n", error->message);
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

	if (!get_secrets (vpn_uuid, vpn_name, retry, allow_interaction,
	                  g_hash_table_lookup (secrets, NM_OPENSWAN_XAUTH_PASSWORD),
	                  &password,
	                  upw_flags,
	                  g_hash_table_lookup (secrets, NM_OPENSWAN_PSK_VALUE),
	                  &group_password,
	                  gpw_flags))
		return 1;

	/* dump the passwords to stdout */
	if (password)
		printf ("%s\n%s\n", NM_OPENSWAN_XAUTH_PASSWORD, password);
	if (group_password)
		printf ("%s\n%s\n", NM_OPENSWAN_PSK_VALUE, group_password);
	printf ("\n\n");

	if (password) {
		memset (password, 0, strlen (password));
		gnome_keyring_memory_free (password);
	}
	if (group_password) {
		memset (group_password, 0, strlen (group_password));
		gnome_keyring_memory_free (group_password);
	}

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
