/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager-libreswan -- Network Manager Libreswan plugin
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
 * (C) Copyright 2004 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <errno.h>
#include <string.h>

#include <libsecret/secret.h>

#include <nma-vpn-password-dialog.h>

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ KEYRING_UUID_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SN_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SK_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GHashTable *attrs;
	GList *list;
	char *secret = NULL;

	attrs = secret_attributes_build (&network_manager_secret_schema,
	                                 KEYRING_UUID_TAG, uuid,
	                                 KEYRING_SN_TAG, NM_SETTING_VPN_SETTING_NAME,
	                                 KEYRING_SK_TAG, secret_name,
	                                 NULL);

	list = secret_service_search_sync (NULL, &network_manager_secret_schema, attrs,
	                                   SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
	                                   NULL, NULL);
	if (list && list->data) {
		SecretItem *item = list->data;
		SecretValue *value = secret_item_get_secret (item);

		if (value) {
			secret = g_strdup (secret_value_get (value, NULL));
			secret_value_unref (value);
		}
	}

	g_list_free_full (list, g_object_unref);
	g_hash_table_unref (attrs);
	return secret;
}

/*****************************************************************/

typedef void (*NoSecretsRequiredFunc) (void);

/* Returns TRUE on success, FALSE on cancel */
typedef gboolean (*AskUserFunc) (const char *vpn_name,
                                 const char *prompt,
                                 gboolean retry,
                                 gboolean need_password,
                                 const char *existing_password,
                                 char **out_new_password,
                                 gboolean need_certpass,
                                 const char *existing_certpass,
                                 char **out_new_certpass);

typedef void (*FinishFunc) (const char *vpn_name,
                            const char *prompt,
                            gboolean allow_interaction,
                            gboolean retry,
                            gboolean need_password,
                            const char *password,
                            gboolean need_certpass,
                            const char *certpass);

/*****************************************************************/
/* External UI mode stuff */

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

static void
eui_no_secrets_required (void)
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();
	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

static void
eui_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean retry,
            gboolean need_password,
            const char *existing_password,
            gboolean need_group_password,
            const char *existing_group_password)
{
	GKeyFile *keyfile;
	gboolean show;

	keyfile = g_key_file_new ();

	g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);

	g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", _("Authenticate VPN"));

	/* If we have an existing password, or we need the user to give us one,
	 * then tell the external UI about the password.  An entry for the password
	 * (possibly pre-populated with the existing password) is only shown to the
	 * user when the password is needed or new secrets are required (retry).
	 * If the password isn't required and there's no existing password, then
	 * just ignore that password completely.
	 */

	if (need_password || existing_password || retry) {
		show = (need_password && !existing_password) || retry;
		keyfile_add_entry_info (keyfile,
		                        NM_LIBRESWAN_KEY_XAUTH_PASSWORD,
		                        existing_password ? existing_password : "",
		                        _("Password"),
		                        TRUE,
		                        show && allow_interaction);
	}

	if (need_group_password || existing_group_password || retry) {
		show = (need_group_password && !existing_group_password) || retry;
		keyfile_add_entry_info (keyfile,
		                        NM_LIBRESWAN_KEY_PSK_VALUE,
		                        existing_group_password ? existing_group_password : "",
		                        _("Group Password"),
		                        TRUE,
		                        show && allow_interaction);
	}

	keyfile_print_stdout (keyfile);
	g_key_file_unref (keyfile);
}

/*****************************************************************/

static void
std_no_secrets_required (void)
{
	printf ("\n\n");
}

static gboolean
std_ask_user (const char *vpn_name,
              const char *prompt,
              gboolean retry,
              gboolean need_password,
              const char *existing_password,
              char **out_new_password,
              gboolean need_group_password,
              const char *existing_group_password,
              char **out_new_group_password)
{
	NMAVpnPasswordDialog *dialog;
	gboolean success = FALSE;

	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (prompt != NULL, FALSE);
	g_return_val_if_fail (out_new_password != NULL, FALSE);
	g_return_val_if_fail (out_new_group_password != NULL, FALSE);

	gtk_init (NULL, NULL);

	dialog = NMA_VPN_PASSWORD_DIALOG (nma_vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));

	/* pre-fill dialog with existing passwords */
	nma_vpn_password_dialog_set_show_password (dialog, need_password);
	if (need_password)
		nma_vpn_password_dialog_set_password (dialog, existing_password);

	nma_vpn_password_dialog_set_show_password_secondary (dialog, need_group_password);
	if (need_group_password) {
		nma_vpn_password_dialog_set_password_secondary_label (dialog, _("_Group Password:"));
		nma_vpn_password_dialog_set_password_secondary (dialog, existing_group_password);
	}

	gtk_widget_show (GTK_WIDGET (dialog));
	if (nma_vpn_password_dialog_run_and_block (dialog)) {
		if (need_password)
			*out_new_password = g_strdup (nma_vpn_password_dialog_get_password (dialog));
		if (need_group_password)
			*out_new_group_password = g_strdup (nma_vpn_password_dialog_get_password_secondary (dialog));
		success = TRUE;
	}

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

static void
std_finish (const char *vpn_name,
            const char *prompt,
            gboolean allow_interaction,
            gboolean finish,
            gboolean need_password,
            const char *password,
            gboolean need_group_password,
            const char *group_password)
{
	/* Send the passwords back to our parent */
	if (password)
		printf ("%s\n%s\n", NM_LIBRESWAN_KEY_XAUTH_PASSWORD, password);
	if (group_password)
		printf ("%s\n%s\n", NM_LIBRESWAN_KEY_PSK_VALUE, group_password);
	printf ("\n\n");

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();
}

/*****************************************************************/

static NMSettingSecretFlags
get_pw_flags (GHashTable *hash, const char *secret_name, const char *mode_name)
{
	const char *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	/* Try new flags value first */
	if (nm_vpn_service_plugin_get_secret_flags (hash, secret_name, &flags))
		return flags;

	/* Otherwise try old "password type" value */
	val = g_hash_table_lookup (hash, mode_name);
	if (val) {
		if (g_strcmp0 (val, NM_LIBRESWAN_PW_TYPE_ASK) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_SAVED;
		else if (g_strcmp0 (val, NM_LIBRESWAN_PW_TYPE_UNUSED) == 0)
			return NM_SETTING_SECRET_FLAG_NOT_REQUIRED;

		/* NM_LIBRESWAN_PW_TYPE_SAVE means FLAG_NONE */
	}

	return NM_SETTING_SECRET_FLAG_NONE;
}

static void
get_existing_passwords (GHashTable *vpn_data,
                        GHashTable *existing_secrets,
                        const char *vpn_uuid,
                        gboolean need_password,
                        gboolean need_group_password,
                        char **out_password,
                        char **out_group_password)
{
	NMSettingSecretFlags upw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags gpw_flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_if_fail (out_password != NULL);
	g_return_if_fail (out_group_password != NULL);

	if (need_password) {
		upw_flags = get_pw_flags (existing_secrets, NM_LIBRESWAN_KEY_XAUTH_PASSWORD, NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES);
		if (!(upw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_password = g_strdup (g_hash_table_lookup (existing_secrets, NM_LIBRESWAN_KEY_XAUTH_PASSWORD));
			if (!*out_password)
				*out_password = keyring_lookup_secret (vpn_uuid, NM_LIBRESWAN_KEY_XAUTH_PASSWORD);
		}
	}

	if (need_group_password) {
		gpw_flags = get_pw_flags (existing_secrets, NM_LIBRESWAN_KEY_PSK_VALUE, NM_LIBRESWAN_KEY_PSK_INPUT_MODES);
		if (!(gpw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			*out_group_password = g_strdup (g_hash_table_lookup (existing_secrets, NM_LIBRESWAN_KEY_PSK_VALUE));
			if (!*out_group_password)
				*out_group_password = keyring_lookup_secret (vpn_uuid, NM_LIBRESWAN_KEY_PSK_VALUE);
		}
	}
}

#define VPN_MSG_TAG "x-vpn-message:"

static char *
get_passwords_required (GHashTable *data,
                        char **hints,
                        gboolean *out_need_password,
                        gboolean *out_need_group_password)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	char *prompt = NULL;
	char **iter;

	/* If hints are given, then always ask for what the hints require */
	if (hints && g_strv_length (hints)) {
		for (iter = hints; iter && *iter; iter++) {
			if (!prompt && g_str_has_prefix (*iter, VPN_MSG_TAG))
				prompt = g_strdup (*iter + strlen (VPN_MSG_TAG));
			else if (strcmp (*iter, NM_LIBRESWAN_KEY_XAUTH_PASSWORD) == 0)
				*out_need_password = TRUE;
			else if (strcmp (*iter, NM_LIBRESWAN_KEY_PSK_VALUE) == 0)
				*out_need_group_password = TRUE;
		}
		return prompt;
	}

	/* User password (XAuth password) */
	flags = get_pw_flags (data, NM_LIBRESWAN_KEY_XAUTH_PASSWORD, NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES);
	if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
		*out_need_password = TRUE;

	/* Group password (IPsec secret) */
	flags = get_pw_flags (data, NM_LIBRESWAN_KEY_PSK_VALUE, NM_LIBRESWAN_KEY_PSK_INPUT_MODES);
	if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
		*out_need_group_password = TRUE;

	return NULL;
}

static void
free_secret (char *p)
{
	if (p) {
		memset (p, 0, strlen (p));
		g_free (p);
	}
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE, external_ui_mode = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	gboolean need_password = FALSE, need_group_password = FALSE;
	char *existing_password = NULL, *existing_group_password = NULL;
	char *new_password = NULL, *new_group_password = NULL;
	GError *error = NULL;
	char **hints = NULL;
	char *prompt = NULL;
	gboolean canceled = FALSE, ask_user = FALSE;

	NoSecretsRequiredFunc no_secrets_required_func = NULL;
	AskUserFunc ask_user_func = NULL;
	FinishFunc finish_func = NULL;

	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
			{ "hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &hints, "Hints from the VPN plugin", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- IPsec auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_add_group (context, gtk_get_option_group (FALSE));

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "Error parsing options: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	g_option_context_free (context);

	if (!vpn_uuid || !vpn_service || !vpn_name) {
		fprintf (stderr, "A connection UUID, name, and VPN plugin service name are required.\n");
		return 1;
	}

	if (   strcmp (vpn_service, NM_VPN_SERVICE_TYPE_LIBRESWAN) != 0
	    && strcmp (vpn_service, NM_VPN_SERVICE_TYPE_OPENSWAN) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_VPN_SERVICE_TYPE_LIBRESWAN);
		return 1;
	}

	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	if (external_ui_mode) {
		no_secrets_required_func = eui_no_secrets_required;
		finish_func = eui_finish;
	} else {
		no_secrets_required_func = std_no_secrets_required;
		ask_user_func = std_ask_user;
		finish_func = std_finish;
	}

	/* Determine which passwords are actually required, either from hints or
	 * from looking at the VPN configuration.
	 */
	prompt = get_passwords_required (data, hints, &need_password, &need_group_password);
	if (!prompt)
		prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network “%s”."), vpn_name);

	/* Exit early if we don't need any passwords */
	if (!need_password && !need_group_password)
		no_secrets_required_func ();
	else {
		get_existing_passwords (data,
		                        secrets,
		                        vpn_uuid,
		                        need_password,
		                        need_group_password,
		                        &existing_password,
		                        &existing_group_password);
		if (need_password && !existing_password)
			ask_user = TRUE;
		if (need_group_password && !existing_group_password)
			ask_user = TRUE;

		/* If interaction is allowed then ask the user, otherwise pass back
		 * whatever existing secrets we can find.
		 */
		if (ask_user_func && allow_interaction && (ask_user || retry)) {
			canceled = !ask_user_func (vpn_name,
			                           prompt,
			                           retry,
			                           need_password,
			                           existing_password,
			                           &new_password,
			                           need_group_password,
			                           existing_group_password,
			                           &new_group_password);
		}

		if (!canceled) {
			finish_func (vpn_name,
			             prompt,
			             allow_interaction,
			             retry,
			             need_password,
			             new_password ? new_password : existing_password,
			             need_group_password,
			             new_group_password ? new_group_password : existing_group_password);
		}

		free_secret (existing_password);
		free_secret (existing_group_password);
		free_secret (new_password);
		free_secret (new_group_password);
	}

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	if (hints)
		g_strfreev (hints);
	g_free (prompt);
	return canceled ? 1 : 0;
}

