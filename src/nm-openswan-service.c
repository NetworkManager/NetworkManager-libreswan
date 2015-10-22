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
#include <stdarg.h>
#include <pty.h>
#include <sys/types.h>

#include <glib/gi18n.h>

#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>
#include "nm-openswan-service.h"
#include "nm-utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

#define NM_TYPE_OPENSWAN_PLUGIN (nm_openswan_plugin_get_type ())
#define NM_OPENSWAN_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENSWAN_PLUGIN, NMOpenSwanPlugin))

typedef NMVpnServicePlugin NMOpenSwanPlugin;
typedef NMVpnServicePluginClass NMOpenSwanPluginClass;

static GType nm_openswan_plugin_get_type (void);

G_DEFINE_TYPE (NMOpenSwanPlugin, nm_openswan_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

/************************************************************/

static gboolean debug = FALSE;
GMainLoop *loop = NULL;

typedef enum {
    CONNECT_STEP_FIRST,
    CONNECT_STEP_CHECK_RUNNING,
    CONNECT_STEP_STACK_INIT,
    CONNECT_STEP_IPSEC_START,
    CONNECT_STEP_WAIT_READY,
    CONNECT_STEP_CONFIG_ADD,
    CONNECT_STEP_CONNECT,
    CONNECT_STEP_LAST
} ConnectStep;

typedef struct {
	GIOChannel *channel;
	guint id;
	GString *str;
	const char *detail;
} Pipe;

typedef struct {
	const char *ipsec_path;
	const char *pluto_path;
	const char *whack_path;
	char *secrets_path;

	gboolean libreswan;
	gboolean interactive;
	gboolean pending_auth;
	gboolean managed;

	GPid pid;
	guint watch_id;
	guint retry_id;
	guint retries;
	ConnectStep connect_step;
	NMConnection *connection;

	GIOChannel *channel;
	guint io_id;
	GString *io_buf;
	char *password;

	Pipe out;
	Pipe err;
} NMOpenSwanPluginPrivate;

#define NM_OPENSWAN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENSWAN_PLUGIN, NMOpenSwanPluginPrivate))

/* NOTE: the helper is currently called explicitly by the ipsec up/down
 * script /usr/libexec/ipsec/_updown.netkey when the configuration contains
 * "nm_configured=yes".  Eventually we want to somehow pass the helper
 * directly to pluto/whack with the --updown option.
 */
#define NM_OPENSWAN_HELPER_PATH		LIBEXECDIR"/nm-openswan-service-helper"

#define DEBUG(...) \
    G_STMT_START { \
        if (debug) { \
            g_message (__VA_ARGS__); \
        } \
    } G_STMT_END

/****************************************************************/

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
	{ NM_OPENSWAN_VENDOR,                     G_TYPE_STRING, 0, 0 },
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
nm_openswan_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     "No VPN configuration options.");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static gboolean
nm_openswan_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (validate_error) {
		g_propagate_error (error, validate_error);
		return FALSE;
	}
	return TRUE;
}

/****************************************************************/

static gboolean connect_step (NMOpenSwanPlugin *self, GError **error);
static gboolean pr_cb (GIOChannel *source, GIOCondition condition, gpointer user_data);

static const char *
_find_helper (const char *progname, const char **paths, GError **error)
{
	const char **iter = paths;
	GString *tmp;
	const char *ret = NULL;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	tmp = g_string_sized_new (50);
	for (iter = paths; iter && *iter; iter++) {
		g_string_append_printf (tmp, "%s%s", *iter, progname);
		if (g_file_test (tmp->str, G_FILE_TEST_EXISTS)) {
			ret = g_intern_string (tmp->str);
			break;
		}
		g_string_set_size (tmp, 0);
	}
	g_string_free (tmp, TRUE);

	if (!ret) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "Could not find %s binary",
		             progname);
	}
	return ret;
}

static const char *
find_helper_bin (const char *progname, GError **error)
{
	static const char *paths[] = {
		PREFIX "/sbin/",
		PREFIX "/bin/",
		"/sbin/",
		"/usr/sbin/",
		"/usr/local/sbin/",
		"/usr/bin/",
		"/usr/local/bin/",
		NULL,
	};

	return _find_helper (progname, paths, error);
}

static const char *
find_helper_libexec (const char *progname, GError **error)
{
	static const char *paths[] = {
		PREFIX "/libexec/ipsec/",
		PREFIX "/lib/ipsec/",
		"/usr/libexec/ipsec/",
		"/usr/local/libexec/ipsec/"
		"/usr/lib/ipsec/",
		"/usr/local/lib/ipsec/",
		NULL,
	};

	return _find_helper (progname, paths, error);
}

static void
pipe_init (Pipe *pipe, int fd, const char *detail)
{
	g_assert (fd >= 0);
	g_assert (detail);
	g_assert (pipe);

	pipe->detail = detail;
	pipe->str = g_string_sized_new (256);
	pipe->channel = g_io_channel_unix_new (fd);
	g_io_channel_set_encoding (pipe->channel, NULL, NULL);
	g_io_channel_set_buffered (pipe->channel, FALSE);
	pipe->id = g_io_add_watch (pipe->channel, G_IO_IN | G_IO_ERR, pr_cb, pipe);
}

static void
pipe_cleanup (Pipe *pipe)
{
	if (pipe->id) {
		g_source_remove (pipe->id);
		pipe->id = 0;
	}
	g_clear_pointer (&pipe->channel, g_io_channel_unref);
	if (pipe->str) {
		g_string_free (pipe->str, TRUE);
		pipe->str = NULL;
	}
}

static void
connect_cleanup (NMOpenSwanPlugin *self)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);

	priv->connect_step = CONNECT_STEP_FIRST;
	priv->pending_auth = FALSE;

	/* Don't remove the child watch since it needs to reap the child */
	priv->watch_id = 0;

	if (priv->pid) {
		kill (priv->pid, SIGTERM);
		priv->pid = 0;
	}

	if (priv->watch_id) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
	}

	if (priv->io_id) {
		g_source_remove (priv->io_id);
		priv->io_id = 0;
	}
	g_clear_pointer (&priv->channel, g_io_channel_unref);

	if (priv->io_buf) {
		g_string_free (priv->io_buf, TRUE);
		priv->io_buf = NULL;
	}

	pipe_cleanup (&priv->out);
	pipe_cleanup (&priv->err);

	if (priv->password) {
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
		priv->password = NULL;
	}
}

static void
delete_secrets_file (NMOpenSwanPlugin *self)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);

	if (priv->secrets_path) {
		unlink (priv->secrets_path);
		g_clear_pointer (&priv->secrets_path, g_free);
	}
}

static gboolean
ipsec_stop (NMOpenSwanPlugin *self, GError **error)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	const char *argv[5];
	guint i = 0;

	if (!priv->connection)
		return TRUE;

	delete_secrets_file (self);
	connect_cleanup (self);

	if (!priv->managed) {
		argv[i++] = priv->ipsec_path;
		argv[i++] = "auto";
		argv[i++] = "--delete";
		argv[i++] = nm_connection_get_uuid (priv->connection);
		argv[i++] = NULL;
	} else if (priv->libreswan) {
		argv[i++] = priv->whack_path;
		argv[i++] = "--shutdown";
		argv[i++] = NULL;
	} else {
		argv[i++] = priv->ipsec_path;
		argv[i++] = "setup";
		argv[i++] = "stop";
		argv[i++] = NULL;
	}

	return g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, NULL, NULL, NULL, error);
}

static void
connect_failed (NMOpenSwanPlugin *self,
                gboolean do_stop,
                GError *error,
                NMVpnConnectionStateReason reason)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);

	if (error) {
		g_warning ("Connect failed: (%s/%d) %s",
		           g_quark_to_string (error->domain),
		           error->code,
		           error->message);
	}

	if (do_stop)
		ipsec_stop (self, NULL);
	g_clear_object (&priv->connection);
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (self), reason);
}

static void
check_running_cb (GPid pid, gint status, gpointer user_data)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	guint ret = 1;
	GError *error = NULL;

	if (priv->watch_id == 0 || priv->pid != pid) {
		/* Reap old child */
		waitpid (pid, NULL, WNOHANG);
		return;
	}

	priv->watch_id = 0;
	priv->pid = 0;

	if (WIFEXITED (status))
		ret = WEXITSTATUS (status);

	DEBUG ("Spawn: child %d exited with status %d", pid, ret);

	/* Reap child */
	waitpid (pid, NULL, WNOHANG);

	if (ret)
		priv->connect_step++;
	else
		priv->connect_step = CONNECT_STEP_WAIT_READY;

	if (!connect_step (self, &error))
		connect_failed (self, TRUE, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	g_clear_error (&error);
}

static gboolean
retry_cb (gpointer user_data)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	GError *error = NULL;

	priv->retry_id = 0;

	if (!connect_step (self, &error))
		connect_failed (self, TRUE, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	g_clear_error (&error);

	return FALSE;
}

static void
child_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	guint ret = 1;
	GError *error = NULL;
	gboolean do_stop = FALSE;

	if (priv->watch_id == 0 || priv->pid != pid) {
		/* Reap old child */
		waitpid (pid, NULL, WNOHANG);
		return;
	}

	priv->watch_id = 0;
	priv->pid = 0;

	DEBUG ("Spawn: child %d exited", pid);

	if (WIFEXITED (status)) {
		ret = WEXITSTATUS (status);
		if (ret)
			g_message ("Spawn: child %d exited with error code %d", pid, ret);
	} else
		g_warning ("Spawn: child %d died unexpectedly", pid);

	/* Reap child */
	waitpid (pid, NULL, WNOHANG);

	if (ret != 0 && priv->retries) {
		priv->retries--;
		g_message ("Spawn: %d more tries...", priv->retries);
		priv->retry_id = g_timeout_add (100, retry_cb, self);
		return;
	}

	if (ret == 0) {
		/* Success; do the next connect step */
		do_stop = TRUE;
		priv->connect_step++;
		priv->retries = 0;
		if (!connect_step (self, &error))
			ret = 1;
	}

	if (ret != 0)
		connect_failed (self, do_stop, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	g_clear_error (&error);
}

static gboolean do_spawn (GPid *out_pid,
                          int *out_stdin,
                          int *out_stderr,
                          GError **error,
                          const char *progname,
                          ...) G_GNUC_NULL_TERMINATED;

static gboolean
do_spawn (GPid *out_pid,
          int *out_stdin,
          int *out_stderr,
          GError **error,
          const char *progname,
          ...)
{
	GError *local = NULL;
	va_list ap;
	GPtrArray *argv;
	char *cmdline, *arg;
	gboolean success;
	GPid pid = 0;

	argv = g_ptr_array_sized_new (10);
	g_ptr_array_add (argv, (char *) progname);

	va_start (ap, progname);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (argv, arg);
	va_end (ap);
	g_ptr_array_add (argv, NULL);

	if (debug) {
		cmdline = g_strjoinv (" ", (char **) argv->pdata);
		g_message ("Spawn: %s", cmdline);
		g_free (cmdline);
	}

	if (out_stdin || out_stderr) {
		success = g_spawn_async_with_pipes (NULL, (char **) argv->pdata, NULL,
		                                    G_SPAWN_DO_NOT_REAP_CHILD,
		                                    NULL, NULL, &pid, out_stdin,
		                                    NULL, out_stderr, &local);
	} else {
		success = g_spawn_async (NULL, (char **) argv->pdata, NULL,
		                         G_SPAWN_DO_NOT_REAP_CHILD,
		                         NULL, NULL, &pid, &local);
	}
	if (success) {
		DEBUG ("Spawn: child process %d", pid);
	} else {
		g_warning ("Spawn failed: (%s/%d) %s",
		           g_quark_to_string (local->domain),
		           local->code, local->message);
		g_propagate_error (error, local);
	}

	if (out_pid)
		*out_pid = pid;

	g_ptr_array_free (argv, TRUE);
	return success;
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

static void
nm_openswan_config_write (gint fd,
                          NMConnection *connection,
                          gboolean libreswan,
                          GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *con_name = nm_connection_get_uuid (connection);
	const char *props_username;
	const char *default_username;
	const char *phase1_alg_str;
	const char *phase2_alg_str;

	g_assert (fd >= 0);
	g_assert (s_vpn);
	g_assert (con_name);

	write_config_option (fd, "conn %s\n", con_name);
	write_config_option (fd, " aggrmode=yes\n");
	write_config_option (fd, " authby=secret\n");
	write_config_option (fd, " left=%%defaultroute\n");
	write_config_option (fd, " leftid=@%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTID));
	write_config_option (fd, " leftxauthclient=yes\n");
	write_config_option (fd, " leftmodecfgclient=yes\n");

	default_username = nm_setting_vpn_get_user_name (s_vpn);
	props_username = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTXAUTHUSER);
	if (   default_username && strlen (default_username)
		&& (!props_username || !strlen (props_username)))
		write_config_option (fd, " leftxauthusername=%s\n", default_username);
	else
		write_config_option (fd, " leftxauthusername=%s\n", props_username);

	write_config_option (fd, " right=%s\n", nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_RIGHT));
	write_config_option (fd, " remote_peer_type=cisco\n");
	write_config_option (fd, " rightxauthserver=yes\n");
	write_config_option (fd, " rightmodecfgserver=yes\n");

	phase1_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_IKE);
	if (!phase1_alg_str || !strlen (phase1_alg_str))
		write_config_option (fd, " ike=aes-sha1\n");
	else
		write_config_option (fd, " ike=%s\n", phase1_alg_str);

	phase2_alg_str = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_ESP);
	if (!phase2_alg_str || !strlen (phase2_alg_str))
		write_config_option (fd, " esp=aes-sha1;modp1024\n");
	else
		write_config_option (fd, " esp=%s\n", phase2_alg_str);

	write_config_option (fd, " nm_configured=yes\n");
	write_config_option (fd, " rekey=yes\n");
	write_config_option (fd, " salifetime=24h\n");
	write_config_option (fd, " ikelifetime=24h\n");
	write_config_option (fd, " keyingtries=1\n");
	if (libreswan && g_strcmp0 (nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_VENDOR), "Cisco") == 0)
		write_config_option (fd, " cisco-unity=yes\n");
	write_config_option (fd, " auto=add");

	/* openswan requires a terminating \n (otherwise it segfaults) while
	 * libreswan fails parsing the configuration if you include the \n.
	 * WTF?
	 */
	if (!libreswan)
		(void) write (fd, "\n", 1);
	if (debug)
		g_print ("\n");
}

static gboolean
nm_openswan_config_psk_write (NMSettingVpn *s_vpn,
                              const char *secrets_path,
                              GError **error)
{
	const char *pw_type, *psk, *leftid;
	int fd;

	/* Check for ignored group password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_PSK_INPUT_MODES);
	if (pw_type && !strcmp (pw_type, NM_OPENSWAN_PW_TYPE_UNUSED))
		return TRUE;

	psk = nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_PSK_VALUE);
	if (!psk)
		return TRUE;

	/* Write the PSK */
	errno = 0;
	fd = open (secrets_path, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "Failed to open secrets file: (%d) %s.",
		             errno, g_strerror (errno));
		return FALSE;
	}

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSWAN_LEFTID);
	g_assert (leftid);
	write_config_option (fd, "@%s: PSK \"%s\"\n", leftid, psk);

	close (fd);
	return TRUE;
}

/****************************************************************/

static gboolean spawn_pty (int *out_stdout,
                           int *out_stderr,
                           int *out_ptyin,
                           GPid *out_pid,
                           GError **error,
                           const char *progname,
                           ...) G_GNUC_NULL_TERMINATED;

static gboolean
spawn_pty (int *out_stdout,
           int *out_stderr,
           int *out_ptyin,
           GPid *out_pid,
           GError **error,
           const char *progname,
           ...)
{
	int pty_master_fd, md;
	int stdout_pipe[2], stderr_pipe[2];
	pid_t child_pid;
	struct termios termios_flags;
	va_list ap;
	GPtrArray *argv;
	char *cmdline, *arg;

	argv = g_ptr_array_sized_new (10);
	g_ptr_array_add (argv, (char *) progname);

	va_start (ap, progname);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (argv, arg);
	va_end (ap);
	g_ptr_array_add (argv, NULL);

	if (debug) {
		cmdline = g_strjoinv (" ", (char **) argv->pdata);
		g_message ("PTY spawn: %s", cmdline);
		g_free (cmdline);
	}

	/* The pipes */
	pipe (stderr_pipe);
	pipe (stdout_pipe);

	/* Fork the command */
	child_pid = forkpty (&pty_master_fd, NULL, NULL, NULL);
	if (child_pid == 0) {
		/* in the child */

		close (2);
		dup (stderr_pipe[1]);
		close (1);
		dup (stdout_pipe[1]);

		/* Close unnecessary pipes */
		close (stderr_pipe[0]);
		close (stdout_pipe[0]);

		if ((md = fcntl (stdout_pipe[1], F_GETFL)) != -1)
			fcntl (stdout_pipe[1], F_SETFL, O_SYNC | md);
		if ((md = fcntl (stderr_pipe[1], F_GETFL)) != -1)
			fcntl (stderr_pipe[1], F_SETFL, O_SYNC | md);

		/* Ensure output is untranslated */
		setenv ("LC_ALL", "C", 1);
		setenv ("LANG", "C", 1);

		execv (argv->pdata[0], (char * const*) argv->pdata);
		g_error ("PTY spawn: cannot exec '%s'", (char *) argv->pdata[0]);
		_exit (-1);
	}

	/* Close child side's pipes */
	close (stderr_pipe[1]);
	close (stdout_pipe[1]);

	if (child_pid < 0) {
		/* Close parent side's pipes */
		close (stderr_pipe[0]);
		close (stdout_pipe[0]);
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn failed for '%s' (%d)",
		             (char *) argv->pdata[0], child_pid);
		g_ptr_array_free (argv, TRUE);
		return FALSE;
	}
	g_ptr_array_free (argv, TRUE);

	/*  Set pipes non-blocking, so we can read big buffers
	 *  in the callback without having to use FIONREAD
	 *  to make sure the callback doesn't block.
	 */
	if ((md = fcntl (stdout_pipe[0], F_GETFL)) != -1)
		fcntl (stdout_pipe[0], F_SETFL, O_NONBLOCK | md);
	if ((md = fcntl (stderr_pipe[0], F_GETFL)) != -1)
		fcntl (stderr_pipe[0], F_SETFL, O_NONBLOCK | md);
	if ((md = fcntl (pty_master_fd, F_GETFL)) != -1)
		fcntl (pty_master_fd, F_SETFL, O_NONBLOCK | md);

	tcgetattr (pty_master_fd, &termios_flags);
	cfmakeraw (&termios_flags);
	cfsetospeed (&termios_flags, __MAX_BAUD);
	tcsetattr (pty_master_fd, TCSANOW, &termios_flags);

	if (out_stdout)
		*out_stdout = stdout_pipe[0];
	if (out_stderr)
		*out_stderr = stderr_pipe[0];
	if (out_ptyin)
		*out_ptyin = pty_master_fd;
	if (out_pid)
		*out_pid = child_pid;

	return TRUE;
}

/****************************************************************/

#define PASSPHRASE_REQUEST "Enter passphrase: "

static gboolean
handle_auth (NMOpenSwanPlugin *self, const char **out_message, const char **out_hint)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	GError *error = NULL;
	gsize bytes_written;

	g_return_val_if_fail (out_message != NULL, FALSE);
	g_return_val_if_fail (out_hint != NULL, FALSE);

	if (priv->password) {
		const char *p = priv->password;

		do {
			g_io_channel_write_chars (priv->channel, p, -1, &bytes_written, &error);
			g_io_channel_flush (priv->channel, NULL);
			if (error) {
				g_warning ("Failed to write password to ipsec: '%s'", error->message);
				g_clear_error (&error);
				return FALSE;
			}
			p += bytes_written;
		} while (*p);

		g_io_channel_write_chars (priv->channel, "\n", -1, NULL, NULL);
		g_io_channel_flush (priv->channel, NULL);

		DEBUG ("PTY: password written");

		/* Don't re-use the password */
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
		priv->password = NULL;
	} else {
		*out_hint = NM_OPENSWAN_XAUTH_PASSWORD;
		*out_message = _("A password is required.");
	}

	return TRUE;
}

static gboolean
io_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	char buf[256];
	GIOStatus status;
	gsize bytes_read = 0;
	gboolean success = FALSE;
	NMVpnConnectionStateReason reason = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	const char *found;

	if (condition & (G_IO_ERR | G_IO_HUP)) {
		g_warning ("PTY spawn: pipe error!");
		goto done;
	}
	g_assert (condition & G_IO_IN);

	status = g_io_channel_read_chars (source, buf, sizeof (buf) - 1, &bytes_read, NULL);
	if (status != G_IO_STATUS_NORMAL || bytes_read == 0)
		return G_SOURCE_CONTINUE;

	buf[bytes_read] = 0;
	if (!buf[0])
		return G_SOURCE_CONTINUE;

	g_string_append (priv->io_buf, buf);
	if (priv->io_buf->len < strlen (PASSPHRASE_REQUEST))
		return G_SOURCE_CONTINUE;

	DEBUG ("VPN request '%s'", priv->io_buf->str);

	found = strstr (priv->io_buf->str, PASSPHRASE_REQUEST);
	if (found) {
		const char *hints[2] = { NULL, NULL };
		const char *message = NULL;

		/* Erase everything up to and including the passphrase request */
		g_string_erase (priv->io_buf, 0, (found + strlen (PASSPHRASE_REQUEST)) - priv->io_buf->str);

		if (!handle_auth (self, &message, &hints[0])) {
			g_warning ("Unhandled management socket request '%s'", buf);
			reason = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			goto done;
		}

		if (message) {
			/* Request new secrets if we need any */
			priv->pending_auth = TRUE;
			if (priv->interactive) {
				DEBUG ("Requesting new secrets: '%s' (%s)", message, hints[0]);
				nm_vpn_service_plugin_secrets_required (NM_VPN_SERVICE_PLUGIN (self), message, hints);
			} else {
				/* Interactive not allowed, can't ask for more secrets */
				g_warning ("More secrets required but cannot ask interactively");
				reason = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
				goto done;
			}
		}
	}
	success = TRUE;

	/* Truncate large buffer if we haven't gotten the password request yet */
	if (priv->io_buf->len > sizeof (buf) * 4)
		g_string_erase (priv->io_buf, 0, sizeof (buf) * 3);

done:
	if (!success) {
		priv->io_id = 0;
		connect_failed (self, TRUE, NULL, reason);
	}
	return success ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static gboolean
pr_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	Pipe *pipe = user_data;
	char buf[200];
	gsize bytes_read = 0;
	char *nl;

	if (condition & (G_IO_ERR | G_IO_HUP)) {
		g_warning ("PTY(%s) pipe error!", pipe->detail);
		return G_SOURCE_REMOVE;
	}
	g_assert (condition & G_IO_IN);

	while (   (g_io_channel_read_chars (source,
	                                    buf,
	                                    sizeof (buf) - 1,
	                                    &bytes_read,
	                                    NULL) == G_IO_STATUS_NORMAL)
	       && bytes_read
	       && pipe->str->len < 500)
		g_string_append_len (pipe->str, buf, bytes_read);

	/* Print each complete line and remove it from the buffer */
	while (pipe->str->len) {
		nl = strpbrk (pipe->str->str, "\n\r");
		if (!nl)
			break;
		*nl = 0;  /* Don't print the linebreak */
		if (pipe->str->str[0])
			DEBUG ("PTY(%s): %s", pipe->detail, pipe->str->str);
		g_string_erase (pipe->str, 0, (nl - pipe->str->str) + 1);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
connect_step (NMOpenSwanPlugin *self, GError **error)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	const char *uuid;
	int fd = -1, up_stdout = -1, up_stderr = -1, up_pty = -1;
	gboolean success = FALSE;

	g_warn_if_fail (priv->watch_id == 0);
	priv->watch_id = 0;
	g_warn_if_fail (priv->pid == 0);
	priv->pid = 0;

	DEBUG ("Connect: step %d", priv->connect_step);

	uuid = nm_connection_get_uuid (priv->connection);
	g_assert (uuid);

	switch (priv->connect_step) {
	case CONNECT_STEP_FIRST:
		/* fall through */
		priv->connect_step++;

	case CONNECT_STEP_CHECK_RUNNING:
		if (!do_spawn (&priv->pid, NULL, NULL, error, priv->ipsec_path, "auto", "--status", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, check_running_cb, self);
		return TRUE;

	case CONNECT_STEP_STACK_INIT:
		if (priv->libreswan) {
			const char *stackman_path;

			stackman_path = find_helper_libexec ("_stackmanager", error);
			if (!stackman_path)
				return FALSE;

			/* Ensure the right IPSec kernel stack is loaded */
			success = do_spawn (&priv->pid, NULL, NULL, error, stackman_path, "start", NULL);
			if (success)
				priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
			return success;
		}
		/* fall through */
		priv->connect_step++;

	case CONNECT_STEP_IPSEC_START:
		/* Start the IPSec service */
		if (priv->libreswan) {
			success = do_spawn (&priv->pid, NULL, NULL, error,
			                    priv->pluto_path, "--config", SYSCONFDIR "/ipsec.conf",
			                    NULL);
		} else
			success = do_spawn (&priv->pid, NULL, NULL, error, priv->ipsec_path, "setup", "start", NULL);
		if (success) {
			priv->managed = TRUE;
			priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		}
		return success;

	case CONNECT_STEP_WAIT_READY:
		if (!priv->retries)
			priv->retries = 30;
		if (!do_spawn (&priv->pid, NULL, NULL, error, priv->ipsec_path, "auto", "--ready", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		return TRUE;

	case CONNECT_STEP_CONFIG_ADD:
		if (!do_spawn (&priv->pid, &fd, NULL, error, priv->ipsec_path,
		               "auto", "--replace", "--config", "-", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		nm_openswan_config_write (fd, priv->connection, priv->libreswan, error);
		close (fd);
		return TRUE;

	case CONNECT_STEP_CONNECT:
		if (!spawn_pty (&up_stdout, &up_stderr, &up_pty, &priv->pid, error,
		                priv->ipsec_path, "auto", "--up", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);

		/* Wait for the password request */
		priv->io_buf = g_string_sized_new (128);
		priv->channel = g_io_channel_unix_new (up_pty);
		g_io_channel_set_encoding (priv->channel, NULL, NULL);
		g_io_channel_set_buffered (priv->channel, FALSE);
		priv->io_id = g_io_add_watch (priv->channel, G_IO_IN | G_IO_ERR | G_IO_HUP, io_cb, self);

		if (debug) {
			pipe_init (&priv->out, up_stdout, "OUT");
			pipe_init (&priv->err, up_stderr, "ERR");
		}
		return TRUE;

	case CONNECT_STEP_LAST:
		/* Everything successfully set up */
		priv->pid = 0;
		connect_cleanup (self);
		return TRUE;
	}

	g_assert_not_reached ();
}

static gboolean
is_libreswan (const char *path)
{
	const char *argv[] = { path, NULL };
	gboolean libreswan = FALSE;
	char *output = NULL;

	if (g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
		libreswan = output && strcasestr (output, " Libreswan ");
		g_free (output);
	}
	return libreswan;
}

static gboolean
_connect_common (NMVpnServicePlugin   *plugin,
                 NMConnection  *connection,
                 GVariant      *details,
                 GError       **error)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (plugin);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *con_name = nm_connection_get_uuid (connection);

	if (debug)
		nm_connection_dump (connection);

	priv->ipsec_path = find_helper_bin ("ipsec", error);
	if (!priv->ipsec_path)
		return FALSE;

	priv->libreswan = is_libreswan (priv->ipsec_path);
	if (priv->libreswan) {
		priv->pluto_path = find_helper_libexec ("pluto", error);
		if (!priv->pluto_path)
			return FALSE;
		priv->whack_path = find_helper_libexec ("whack", error);
		if (!priv->whack_path)
			return FALSE;
	}

	ipsec_stop (self, NULL);

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	if (!nm_openswan_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_openswan_secrets_validate (s_vpn, error))
		return FALSE;

	if (priv->connect_step != CONNECT_STEP_FIRST) {
		g_set_error_literal (error,
			                 NM_VPN_PLUGIN_ERROR,
			                 NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			                 "Already connecting!");
		return FALSE;
	}

	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD));

	/* Write the IPSec secret (group password); *SWAN always requires this and
	 * doesn't ask for it interactively.
	 */
	priv->secrets_path = g_strdup_printf (SYSCONFDIR "/ipsec.d/ipsec-%s.secrets", con_name);
	if (!nm_openswan_config_psk_write (s_vpn, priv->secrets_path, error))
		return FALSE;

	priv->connection = g_object_ref (connection);

	/* Start the connection process */
	return connect_step (self, error);
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	return _connect_common (plugin, connection, NULL, error);
}

static gboolean
real_connect_interactive (NMVpnServicePlugin   *plugin,
                          NMConnection  *connection,
                          GVariant      *details,
                          GError       **error)
{
	if (!_connect_common (plugin, connection, details, error))
		return FALSE;

	NM_OPENSWAN_PLUGIN_GET_PRIVATE (plugin)->interactive = TRUE;
	return TRUE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	const char *pw_type;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
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

static gboolean
real_new_secrets (NMVpnServicePlugin *plugin,
                  NMConnection *connection,
                  GError **error)
{
	NMOpenSwanPlugin *self = NM_OPENSWAN_PLUGIN (plugin);
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *message = NULL;
	const char *hints[] = { NULL, NULL };

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	DEBUG ("VPN received new secrets; sending to ipsec");

	g_free (priv->password);
	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD));

	g_warn_if_fail (priv->pending_auth);
	if (!handle_auth (self, &message, &hints[0])) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_FAILED,
		                     _("Unhandled pending authentication."));
		return FALSE;
	}

	/* Request new secrets if we need any */
	if (message) {
		DEBUG ("Requesting new secrets: '%s'", message);
		nm_vpn_service_plugin_secrets_required (plugin, message, hints);
	}

	return TRUE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **error)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (plugin);
	gboolean ret;

	ret = ipsec_stop (NM_OPENSWAN_PLUGIN (plugin), error);
	g_clear_object (&priv->connection);

	return ret;
}

static void
nm_openswan_plugin_init (NMOpenSwanPlugin *plugin)
{
}

static void
finalize (GObject *object)
{
	NMOpenSwanPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (object);

	delete_secrets_file (NM_OPENSWAN_PLUGIN (object));
	connect_cleanup (NM_OPENSWAN_PLUGIN (object));
	g_clear_object (&priv->connection);

	G_OBJECT_CLASS (nm_openswan_plugin_parent_class)->finalize (object);
}

static void
nm_openswan_plugin_class_init (NMOpenSwanPluginClass *openswan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (openswan_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (openswan_class);

	g_type_class_add_private (object_class, sizeof (NMOpenSwanPluginPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	parent_class->connect = real_connect;
	parent_class->connect_interactive = real_connect_interactive;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
	parent_class->new_secrets = real_new_secrets;
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
quit_mainloop (NMOpenSwanPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMOpenSwanPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	GError *error = NULL;

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
		_("This service provides integrated IPsec VPN capability to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("OPENSWAN_DEBUG") || getenv ("IPSEC_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("%s (version " DIST_VERSION ") starting...", argv[0]);

	plugin = g_initable_new (NM_TYPE_OPENSWAN_PLUGIN, NULL, &error,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_OPENSWAN,
	                         NULL);
	if (!plugin) {
                g_warning ("Failed to initialize a plugin instance: %s", error->message);
                g_error_free (error);
		exit (1);
	}

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	setup_signals ();
	g_main_loop_run (loop);

	g_main_loop_unref (loop);
	g_object_unref (plugin);

	exit (0);
}
