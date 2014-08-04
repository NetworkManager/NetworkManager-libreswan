/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager-openswan -- Network Manager Openswan plugin
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
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <locale.h>

#include <glib/gi18n.h>

#include <nm-setting-vpn.h>
#include "nm-openswan-service.h"
#include "nm-utils.h"

#include <sys/types.h>

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
GMainLoop *loop = NULL;

G_DEFINE_TYPE (NMOPENSWANPlugin, nm_openswan_plugin, NM_TYPE_VPN_PLUGIN)

typedef struct {
	GPid pid;
} NMOPENSWANPluginPrivate;

#define NM_OPENSWAN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENSWAN_PLUGIN, NMOPENSWANPluginPrivate))

static const char *openswan_binary_paths[] =
{
	"/usr/sbin/ipsec",
	"/sbin/ipsec",
	"/usr/local/sbin/ipsec",
	NULL
};

#define NM_OPENSWAN_HELPER_PATH		LIBEXECDIR"/nm-openswan-service-helper"

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_OPENSWAN_RIGHT,                      G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_LEFTID,                     G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_LEFTXAUTHUSER,              G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_DOMAIN,                     G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_DHGROUP,                    G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_PFSGROUP,                   G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_DPDTIMEOUT,                 G_TYPE_INT, 0, 86400 },
	{ NM_OPENSWAN_IKE,                        G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_ESP,                        G_TYPE_STRING, 0, 0 },
	/* Ignored option for internal use */
	{ NM_OPENSWAN_PSK_INPUT_MODES,            G_TYPE_NONE, 0, 0 },
	{ NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES, G_TYPE_NONE, 0, 0 },
	{ NM_OPENSWAN_PSK_VALUE "-flags",         G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_XAUTH_PASSWORD "-flags",    G_TYPE_STRING, 0, 0 },
	{ NULL,                                   G_TYPE_NONE, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_OPENSWAN_PSK_VALUE,                  G_TYPE_STRING, 0, 0 },
	{ NM_OPENSWAN_XAUTH_PASSWORD,             G_TYPE_STRING, 0, 0 },
	{ NULL,                                   G_TYPE_NONE, 0, 0 }
};

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_NONE:
			return; /* technically valid, but unused */
		case G_TYPE_STRING:
			return; /* valid */
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid integer property '%s' or out of range [%d -> %d]",
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             key);
	}
}

static gboolean
nm_openswan_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_openswan_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void
pluto_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMOPENSWANPlugin *plugin = NM_OPENSWAN_PLUGIN (user_data);
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (debug)
		g_message ("pluto_watch: current child pid = %d, pluto pid=%d", pid, priv->pid);

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning ("pluto_watch: pluto exited with error code %d", error);
	} else if (WIFSTOPPED (status))
		g_warning ("pluto_watch: pluto stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("pluto_watch: pluto died with signal %d", WTERMSIG (status));
	else
		g_warning ("pluto_watch: pluto died from an unknown cause");

	/* Reap child if needed. */
	waitpid (pid, NULL, WNOHANG);

	if (debug)
		g_message ("pluto_watch: reaped child pid %d", pid);

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	if(pid == priv->pid || error) {
		priv->pid = 0;

		if (debug)
			g_message ("pluto_watch: nm pluto service is stopping");

		nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
	}

	if (debug)
		g_message ("pluto_watch: nm pluto service will continue after reaping a child");

	/*closing pid*/
	g_spawn_close_pid (pid);
}

static gint
nm_openswan_start_openswan_binary (NMOPENSWANPlugin *plugin, GError **error)
{
	GPid pid, pid_auto;
	const char **openswan_binary = NULL;
	GPtrArray *openswan_argv;
	gint stdin_fd;

	/* Find openswan ipsec */
	openswan_binary = openswan_binary_paths;
	while (*openswan_binary != NULL) {
		if (g_file_test (*openswan_binary, G_FILE_TEST_EXISTS))
			break;
		openswan_binary++;
	}

	if (!*openswan_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find openswan binary.");
		return -1;
	}

	openswan_argv = g_ptr_array_new ();
	g_ptr_array_add (openswan_argv, (gpointer) (*openswan_binary));
	g_ptr_array_add (openswan_argv, (gpointer) "setup");
	g_ptr_array_add (openswan_argv, (gpointer) "start");
	g_ptr_array_add (openswan_argv, NULL);

	if (!g_spawn_async (NULL, (char **) openswan_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		g_ptr_array_free (openswan_argv, TRUE);
		g_warning ("pluto failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openswan_argv, TRUE);

	g_message ("ipsec/pluto started with pid %d", pid);

	NM_OPENSWAN_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	g_child_watch_add (pid, (GChildWatchFunc) pluto_watch_cb, plugin);

	sleep(2);

	openswan_argv = g_ptr_array_new ();
	g_ptr_array_add (openswan_argv, (gpointer) (*openswan_binary));
	g_ptr_array_add (openswan_argv, (gpointer) "auto");
	g_ptr_array_add (openswan_argv, (gpointer) "--add");
	g_ptr_array_add (openswan_argv, (gpointer) "--config");
	g_ptr_array_add (openswan_argv, (gpointer) "-");
	g_ptr_array_add (openswan_argv, (gpointer) "nm-conn1");
	g_ptr_array_add (openswan_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) openswan_argv->pdata, NULL,
	                               G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid_auto, &stdin_fd,
	                               NULL, NULL, error)) {
		g_ptr_array_free (openswan_argv, TRUE);
		g_warning ("ipsec auto add failed with error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openswan_argv, TRUE);

	if (debug)
		g_message ("pluto auto started with pid %d", pid_auto);

	g_child_watch_add (pid_auto, (GChildWatchFunc) pluto_watch_cb, plugin);

	return stdin_fd;
}

static gint
nm_openswan_start_openswan_connection (NMOPENSWANPlugin *plugin, GError **error)
{
	GPid pid;
	const char **openswan_binary = NULL;
	GPtrArray *openswan_argv;
	gint stdin_fd;

	/* Find openswan ipsec */
	openswan_binary = openswan_binary_paths;
	while (*openswan_binary != NULL) {
		if (g_file_test (*openswan_binary, G_FILE_TEST_EXISTS))
			break;
		openswan_binary++;
	}

	if (!*openswan_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find openswan binary.");
		return -1;
	}

	openswan_argv = g_ptr_array_new ();
	g_ptr_array_add (openswan_argv, (gpointer) (*openswan_binary));
	g_ptr_array_add (openswan_argv, (gpointer) "auto");
	g_ptr_array_add (openswan_argv, (gpointer) "--up");
	g_ptr_array_add (openswan_argv, (gpointer) "nm-conn1");
	g_ptr_array_add (openswan_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) openswan_argv->pdata, NULL,
	                               G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
	                               NULL, NULL, error)) {
		g_ptr_array_free (openswan_argv, TRUE);
		g_warning ("ipsec/pluto auto connection failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openswan_argv, TRUE);

	if (debug)
		g_message ("pluto up started with pid %d", pid);

	g_child_watch_add (pid, (GChildWatchFunc) pluto_watch_cb, plugin);

	return stdin_fd;
}

static inline void
write_config_option (int fd, const char *format, ...)
{
	char *string;
	va_list args;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);

	if (debug)
		g_print ("Config: %s", string);

	if ( write (fd, string, strlen (string)) == -1)
		g_warning ("nm-openswan: error in write_config_option");

	g_free (string);
	va_end (args);
}

typedef struct {
	//int fd;
	int conf_fd;
	int secret_fd;
	NMSettingVPN *s_vpn;
	GError *error;
	gboolean upw_ignored;
	gboolean gpw_ignored;
} WriteConfigInfo;

static void
write_one_property (const char *key, const char *value, gpointer user_data)
{
	WriteConfigInfo *info = (WriteConfigInfo *) user_data;
	GType type = G_TYPE_INVALID;
	int i;
	//const char *default_username;
	//const char *props_username;
	const char *leftid;

	if (info->error)
		return;

	/* Find the value in the table to get its type */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];

		if (!strcmp (prop.name, (char *) key)) {
			/* Property is ok */
			type = prop.type;
			break;
		}
	}

	/* Try the valid secrets table */
	for (i = 0; type == G_TYPE_INVALID && valid_secrets[i].name; i++) {
		ValidProperty prop = valid_secrets[i];

		if (!strcmp (prop.name, (char *) key)) {
			/* Property is ok */
			type = prop.type;
			break;
		}
	}

	if (type == G_TYPE_INVALID) {
		g_set_error (&info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Config option '%s' invalid or unknown.",
		             (const char *) key);
	}

	/* Don't write ignored secrets */
	if (!strcmp (key, NM_OPENSWAN_XAUTH_PASSWORD) && info->upw_ignored)
		return;
	if (!strcmp (key, NM_OPENSWAN_PSK_VALUE) && info->gpw_ignored)
		return;

	if (type == G_TYPE_STRING) {
		//write_config_option (info->fd, "%s %s\n", (char *) key, (char *) value);

		if (!strcmp (key, NM_OPENSWAN_PSK_VALUE)) {
			leftid=nm_setting_vpn_get_data_item (info->s_vpn, NM_OPENSWAN_LEFTID);
			write_config_option (info->secret_fd, "@%s: PSK \"%s\"\n", leftid, (char *) value);
		}

		/*if (!strcmp (key, NM_OPENSWAN_XAUTH_PASSWORD)) {
		default_username = nm_setting_vpn_get_user_name (info->s_vpn);
		props_username = nm_setting_vpn_get_data_item (info->s_vpn, NM_OPENSWAN_LEFTXAUTHUSER);
			if ( default_username && strlen (default_username)
				&& (!props_username || !strlen (props_username))) {
			write_config_option (info->secret_fd, "@%s : XAUTH \"%s\"\n",default_username, (char *) value);
			} else {
			write_config_option (info->secret_fd, "@%s : XAUTH \"%s\"\n", props_username, (char *) value);
			}
		}*/

	} else if (type == G_TYPE_BOOLEAN) {
		if (!strcmp (value, "yes")) {
			//write_config_option (info->fd, "%s\n", (char *) key);
		}
	} else if (type == G_TYPE_INT) {
		long int tmp_int;
		char *tmp_str;

		/* Convert -> int and back to string for security's sake since
		 * strtol() ignores leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			tmp_str = g_strdup_printf ("%ld", tmp_int);
			//write_config_option (info->fd, "%s %s\n", (char *) key, tmp_str);
			g_free (tmp_str);
		} else {
			g_set_error (&info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Config option '%s' not an integer.",
			             (const char *) key);
		}
	} else if (type == G_TYPE_NONE) {
		/* ignored */
	} else {
		/* Just ignore unknown properties */
		g_warning ("Don't know how to write property '%s' with type %s",
		           (char *) key, g_type_name (type));
	}
}

static gboolean
nm_openswan_config_write (gint openswan_fd, NMSettingVPN *s_vpn, GError **error)
{
	WriteConfigInfo *info;
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;
	gint fdtmp1=-1;

	fdtmp1 = openswan_fd;
	if (fdtmp1 != -1) {
		write_config_option (fdtmp1, "conn nm-conn1\n");
		write_config_option (fdtmp1, " aggrmode=yes\n");
		write_config_option (fdtmp1, " authby=secret\n");
		write_config_option (fdtmp1, " left=%%defaultroute\n");
		write_config_option (fdtmp1, " leftid=@%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTID));
		write_config_option (fdtmp1, " leftxauthclient=yes\n");
		write_config_option (fdtmp1, " leftmodecfgclient=yes\n");

		default_username = nm_setting_vpn_get_user_name (s_vpn);
		props_username = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER);
		if (   default_username && strlen (default_username)
			&& (!props_username || !strlen (props_username)))
			write_config_option (fdtmp1, " leftxauthusername=%s\n", default_username);
		else
			write_config_option (fdtmp1, " leftxauthusername=%s\n", props_username);

		write_config_option (fdtmp1, " right=%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_RIGHT));
		write_config_option (fdtmp1, " remote_peer_type=cisco\n");
		write_config_option (fdtmp1, " rightxauthserver=yes\n");
		write_config_option (fdtmp1, " rightmodecfgserver=yes\n");

		phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_IKE);
		if (!phase1_alg_str || !strlen (phase1_alg_str))
			write_config_option (fdtmp1, " ike=aes-sha1\n");
		else
			write_config_option (fdtmp1, " ike=%s\n", phase1_alg_str);

		phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_ESP);
		if (!phase2_alg_str || !strlen (phase2_alg_str))
			write_config_option (fdtmp1, " esp=aes-sha1;modp1024\n");
		else
			write_config_option (fdtmp1, " esp=%s\n", phase2_alg_str);

		write_config_option (fdtmp1, " nm_configured=yes\n");
		write_config_option (fdtmp1, " rekey=yes\n");
		write_config_option (fdtmp1, " salifetime=24h\n");
		write_config_option (fdtmp1, " ikelifetime=24h\n");
		write_config_option (fdtmp1, " keyingtries=1\n");
		write_config_option (fdtmp1, " auto=add");
	}

	info = g_malloc0 (sizeof (WriteConfigInfo));
	info->conf_fd = openswan_fd;
	info->s_vpn = s_vpn;

	nm_setting_vpn_foreach_data_item (s_vpn, write_one_property, info);
	*error = info->error;
	close (openswan_fd);
	sleep (3);
	g_free (info);

	return *error ? FALSE : TRUE;
}

static gboolean
nm_openswan_config_secret_write (NMSettingVPN *s_vpn, GError **error)
{
	WriteConfigInfo *info;
	//const char *props_username;
	//const char *default_username;
	const char *pw_type;
	//gint fdtmp1=-1;
	//gint conf_fd=-1;
	gint secret_fd=-1;

	secret_fd = open ("/etc/ipsec.d/ipsec-nm-conn1.secrets", O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	
	info = g_malloc0 (sizeof (WriteConfigInfo));
	info->secret_fd = secret_fd;
	info->s_vpn = s_vpn;

	/* Check for ignored user password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES);
	if (pw_type && !strcmp (pw_type, NM_OPENSWAN_PW_TYPE_UNUSED))
		info->upw_ignored = TRUE;

	/* Check for ignored group password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_PSK_INPUT_MODES);
	if (pw_type && !strcmp (pw_type, NM_OPENSWAN_PW_TYPE_UNUSED))
		info->gpw_ignored = TRUE;

	nm_setting_vpn_foreach_secret (s_vpn, write_one_property, info);
	*error = info->error;
	close (secret_fd);
	g_free (info);

	return *error ? FALSE : TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	gint openswan_fd = -1;
	gboolean success = FALSE;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	if (!nm_openswan_properties_validate (s_vpn, error))
		goto out;

	if (!nm_openswan_secrets_validate (s_vpn, error))
		goto out;

	if (!nm_openswan_config_secret_write (s_vpn, error))
		goto out;

	openswan_fd = nm_openswan_start_openswan_binary (NM_OPENSWAN_PLUGIN (plugin), error);
	if (openswan_fd < 0)
		goto out;

	if (debug)
		nm_connection_dump (connection);

	if (!nm_openswan_config_write (openswan_fd, s_vpn, error)) {
		goto out;
	} else {
		/*no error*/
		openswan_fd = -1;
	}

	unlink("/etc/ipsec.d/ipsec-nm-conn1.secrets");  

	openswan_fd = nm_openswan_start_openswan_connection (NM_OPENSWAN_PLUGIN (plugin), error);
	if (openswan_fd < 0)
		goto out;

	write_config_option (openswan_fd, "%s", nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD));
	close(openswan_fd);
	openswan_fd=-1;

	success = TRUE;

out:
	if (openswan_fd >= 0)
		close (openswan_fd);

	return success;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;
	const char *pw_type;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_PSK_INPUT_MODES);
	if (!pw_type || strcmp (pw_type, NM_OPENSWAN_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_PSK_VALUE)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD_INPUT_MODES);
	if (!pw_type || strcmp (pw_type, NM_OPENSWAN_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

	return FALSE;
}

#if 0
static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}
#endif

static gboolean
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **error)
{
	const char **openswan_binary = NULL;
	GPtrArray *openswan_argv;

	/* Find openswan */
	openswan_binary = openswan_binary_paths;
	while (*openswan_binary != NULL) {
		if (g_file_test (*openswan_binary, G_FILE_TEST_EXISTS))
			break;
		openswan_binary++;
	}

	if (!*openswan_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find openswan binary.");
		return -1;
	}

	openswan_argv = g_ptr_array_new ();
	g_ptr_array_add (openswan_argv, (gpointer) (*openswan_binary));
	g_ptr_array_add (openswan_argv, (gpointer) "setup");
	g_ptr_array_add (openswan_argv, (gpointer) "stop");
	g_ptr_array_add (openswan_argv, NULL);

	if (!g_spawn_async (NULL, (char **) openswan_argv->pdata, NULL,
	                    0, NULL, NULL, NULL, error)) {
		g_ptr_array_free (openswan_argv, TRUE);
		g_warning ("pluto failed to stop.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (openswan_argv, TRUE);

	return TRUE;
}

static void
nm_openswan_plugin_init (NMOPENSWANPlugin *plugin)
{
}

static void
nm_openswan_plugin_class_init (NMOPENSWANPluginClass *openswan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (openswan_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (openswan_class);

	g_type_class_add_private (object_class, sizeof (NMOPENSWANPluginPrivate));

	/* virtual methods */
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMOPENSWANPlugin *
nm_openswan_plugin_new (void)
{
	return (NMOPENSWANPlugin *) g_object_new (NM_TYPE_OPENSWAN_PLUGIN,
	                                          NM_VPN_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_OPENSWAN,
	                                          NULL);
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
		g_main_loop_quit (loop);
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

static void
quit_mainloop (NMOPENSWANPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMOPENSWANPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_OPENSWAN_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		_("nm-openswan-service provides integrated IPsec VPN capability to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("OPENSWAN_DEBUG") || getenv ("IPSEC_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("%s (version " DIST_VERSION ") starting...", argv[0]);

	plugin = nm_openswan_plugin_new ();
	if (!plugin)
		exit (1);

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	setup_signals ();
	g_main_loop_run (loop);

	g_main_loop_unref (loop);
	g_object_unref (plugin);

	exit (0);
}
