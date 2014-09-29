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

typedef enum {
    CONNECT_STEP_FIRST,
    CONNECT_STEP_IPSEC_START,
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
	char *secrets_path;

	GPid pid;
	guint watch_id;
	ConnectStep connect_step;
	NMConnection *connection;

	GIOChannel *channel;
	guint io_id;
	GString *io_buf;
	char *password;

	Pipe out;
	Pipe err;
} NMOPENSWANPluginPrivate;

#define NM_OPENSWAN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENSWAN_PLUGIN, NMOPENSWANPluginPrivate))

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
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
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
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

/****************************************************************/

static gboolean connect_step (NMOPENSWANPlugin *self, GError **error);
static gboolean pr_cb (GIOChannel *source, GIOCondition condition, gpointer user_data);

static const char *ipsec_paths[] =
{
	"/usr/sbin/ipsec",
	"/sbin/ipsec",
	"/usr/local/sbin/ipsec",
	NULL
};

static const char *
find_ipsec (GError **error)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (ipsec_paths); i++) {
		if (g_file_test (ipsec_paths[i], G_FILE_TEST_EXISTS))
			return ipsec_paths[i];
	}

	g_set_error_literal (error,
	                     NM_VPN_PLUGIN_ERROR,
	                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
	                     "Could not find ipsec binary.");
	return NULL;
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
connect_cleanup (NMOPENSWANPlugin *self)
{
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);

	priv->connect_step = CONNECT_STEP_FIRST;

	/* Don't remove the child watch since it needs to reap the child */
	priv->watch_id = 0;

	if (priv->pid) {
		kill (priv->pid, SIGTERM);
		priv->pid = 0;
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

	g_clear_object (&priv->connection);
}

static void
delete_secrets_file (NMOPENSWANPlugin *self)
{
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);

	if (priv->secrets_path) {
		unlink (priv->secrets_path);
		g_clear_pointer (&priv->secrets_path, g_free);
	}
}

static gboolean
ipsec_stop (NMOPENSWANPlugin *self, GError **error)
{
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	const char *argv[4] = { priv->ipsec_path, "setup", "stop", NULL };

	delete_secrets_file (self);
	return g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, NULL, NULL, NULL, error);
}

static void
connect_failed (NMOPENSWANPlugin *self, gboolean do_stop, GError *error)
{
	if (error) {
		g_warning ("Connect failed: (%s/%d) %s",
		           g_quark_to_string (error->domain),
		           error->code,
		           error->message);
	}

	connect_cleanup (self);
	if (do_stop)
		ipsec_stop (self, NULL);
	nm_vpn_plugin_failure (NM_VPN_PLUGIN (self), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
}

static void
pluto_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMOPENSWANPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
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
			g_warning ("Spawn: child %d exited with error code %d", pid, ret);
	} else
		g_warning ("Spawn: child %d died unexpectedly", pid);

	/* Reap child */
	waitpid (pid, NULL, WNOHANG);

	if (ret == 0) {
		/* Success; do the next connect step */
		do_stop = TRUE;
		priv->connect_step++;
		if (!connect_step (self, &error))
			ret = 1;
	}

	if (ret != 0)
		connect_failed (self, do_stop, error);
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
nm_openswan_config_write (gint fd, NMConnection *connection, GError **error)
{
	NMSettingVPN *s_vpn = nm_connection_get_setting_vpn (connection);
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
	write_config_option (fd, " auto=add\n");
}

static gboolean
nm_openswan_config_psk_write (NMSettingVPN *s_vpn,
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
	g_ptr_array_free (argv, TRUE);

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
		return FALSE;
	}

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
io_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMOPENSWANPlugin *self = NM_OPENSWAN_PLUGIN (user_data);
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	char buf[256];
	GIOStatus status;
	gsize bytes_read = 0;
	gboolean ret = G_SOURCE_CONTINUE;
	guint blank;

	if (condition & (G_IO_ERR | G_IO_HUP)) {
		g_warning ("PTY spawn: pipe error!");
		ret = G_SOURCE_REMOVE;
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
	DEBUG ("VPN request '%s'", priv->io_buf->str);
	if (priv->io_buf->len < strlen (PASSPHRASE_REQUEST))
		return G_SOURCE_CONTINUE;

	if (priv->io_buf->len > 1024) {
		ret = G_SOURCE_REMOVE;
		goto done;
	}

	/* Strip leading whitespace */
	blank = 0;
	while (g_ascii_isspace (priv->io_buf->str[blank]))
		blank++;
	if (blank)
		g_string_erase (priv->io_buf, 0, blank);

	if (strcmp (priv->io_buf->str, PASSPHRASE_REQUEST) == 0) {
		GError *error = NULL;
		gsize bytes_written;
		const char *password = priv->password;

		g_string_erase (priv->io_buf, 0, strlen (PASSPHRASE_REQUEST));

		if (!password) {
			/* FIXME: request new password interactively */
			g_warning ("Password required but not provided!");
			ret = G_SOURCE_REMOVE;
			goto done;
		}

		do {
			g_io_channel_write_chars (source, password, -1, &bytes_written, &error);
			g_io_channel_flush (source, NULL);
			if (error) {
				g_warning ("Failed to write password to ipsec!");
				ret = G_SOURCE_REMOVE;
				goto done;
			}
			password += bytes_written;
		} while (*password);

		g_io_channel_write_chars (source, "\n", -1, NULL, NULL);
		g_io_channel_flush (source, NULL);

		DEBUG ("PTY: password written");
	}

done:
	if (ret == G_SOURCE_REMOVE) {
		priv->io_id = 0;
		connect_failed (self, TRUE, NULL);
	}
	return ret;
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
connect_step (NMOPENSWANPlugin *self, GError **error)
{
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	const char *uuid;
	int fd = -1, up_stdout = -1, up_stderr = -1, up_pty = -1;

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

	case CONNECT_STEP_IPSEC_START:
		/* Start the IPSec service */
		if (!do_spawn (&priv->pid, NULL, NULL, error, priv->ipsec_path, "setup", "start", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, pluto_watch_cb, self);
		return TRUE;

	case CONNECT_STEP_CONFIG_ADD:
		if (!do_spawn (&priv->pid, &fd, NULL, error, priv->ipsec_path,
		               "auto", "--add", "--config", "-", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, pluto_watch_cb, self);
		nm_openswan_config_write (fd, priv->connection, error);
		close (fd);
		return TRUE;

	case CONNECT_STEP_CONNECT:
		if (!spawn_pty (&up_stdout, &up_stderr, &up_pty, &priv->pid, error,
		                priv->ipsec_path, "auto", "--up", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, pluto_watch_cb, self);

		/* Wait for the password request */
		priv->io_buf = g_string_sized_new (128);
		priv->channel = g_io_channel_unix_new (up_pty);
		g_io_channel_set_encoding (priv->channel, NULL, NULL);
		g_io_channel_set_buffered (priv->channel, FALSE);
		priv->io_id = g_io_add_watch (priv->channel, G_IO_IN | G_IO_ERR, io_cb, self);

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
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMOPENSWANPlugin *self = NM_OPENSWAN_PLUGIN (plugin);
	NMOPENSWANPluginPrivate *priv = NM_OPENSWAN_PLUGIN_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	const char *con_name = nm_connection_get_uuid (connection);

	if (debug)
		nm_connection_dump (connection);

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

	priv->ipsec_path = find_ipsec (error);
	if (!priv->ipsec_path)
		return FALSE;

	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENSWAN_XAUTH_PASSWORD));

	/* Write the IPSec secret (group password) */
	priv->secrets_path = g_strdup_printf (SYSCONFDIR "/ipsec.d/ipsec-%s.secrets", con_name);
	if (!nm_openswan_config_psk_write (s_vpn, priv->secrets_path, error))
		return FALSE;

	priv->connection = g_object_ref (connection);

	/* Start the connection process */
	return connect_step (self, error);
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
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
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
real_disconnect (NMVPNPlugin *plugin, GError **error)
{
	connect_cleanup (NM_OPENSWAN_PLUGIN (plugin));
	return ipsec_stop (NM_OPENSWAN_PLUGIN (plugin), error);
}

static void
nm_openswan_plugin_init (NMOPENSWANPlugin *plugin)
{
}

static void
finalize (GObject *object)
{
	delete_secrets_file (NM_OPENSWAN_PLUGIN (object));
	connect_cleanup (NM_OPENSWAN_PLUGIN (object));

	G_OBJECT_CLASS (nm_openswan_plugin_parent_class)->finalize (object);
}

static void
nm_openswan_plugin_class_init (NMOPENSWANPluginClass *openswan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (openswan_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (openswan_class);

	g_type_class_add_private (object_class, sizeof (NMOPENSWANPluginPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	parent_class->connect = real_connect;
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
