/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager-libreswan -- Network Manager Libreswan plugin
 *
 * Dan Williams <dcbw@redhat.com>
 * Avesh Agarwal <avagarwa@redhat.com>
 * Lubomir Rintel <lkundrak@v3.sk>
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
 * Copyright (C) 2010 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#define _GNU_SOURCE 1

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>

#define _LINUX_IN6_H 1
#include <linux/xfrm.h>

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
#include <glib/gstdio.h>

#include "nm-libreswan-helper-service-dbus.h"
#include "utils.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-vpn/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

#define NM_TYPE_LIBRESWAN_PLUGIN (nm_libreswan_plugin_get_type ())
#define NM_LIBRESWAN_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_LIBRESWAN_PLUGIN, NMLibreswanPlugin))

typedef NMVpnServicePlugin NMLibreswanPlugin;
typedef NMVpnServicePluginClass NMLibreswanPluginClass;

static GType nm_libreswan_plugin_get_type (void);

G_DEFINE_TYPE (NMLibreswanPlugin, nm_libreswan_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

/************************************************************/

static struct {
	gboolean debug;
	int log_level;
	GMainLoop *loop;
} gl/*obal*/;

typedef enum {
    CONNECT_STEP_FIRST,
    CONNECT_STEP_CHECK_RUNNING,
    CONNECT_STEP_STACK_INIT,
    CONNECT_STEP_CHECK_NSS,
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

	gboolean openswan;
	gboolean interactive;
	gboolean pending_auth;
	gboolean managed;

	GPid pid;
	guint watch_id;
	guint retry_id;
	guint retries;
	guint quit_blockers;
	ConnectStep connect_step;
	NMConnection *connection;
	NMDBusLibreswanHelper *dbus_skeleton;
	GPtrArray *routes;

	GIOChannel *channel;
	guint io_id;
	GString *io_buf;
	char *password;

	Pipe out;
	Pipe err;
} NMLibreswanPluginPrivate;

#define NM_LIBRESWAN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LIBRESWAN_PLUGIN, NMLibreswanPluginPrivate))

/****************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
              g_print ("nm-libreswan[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                       (long) getpid (), \
                       nm_utils_syslog_to_str (level) \
                       _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

static gboolean
_LOGD_enabled (void)
{
    return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(LOG_EMERG, __VA_ARGS__)

static void
_debug_write_option (const char *setting)
{
	_LOGD ("Config %s", setting);
}

/****************************************************************/

guint32
nm_utils_ip4_prefix_to_netmask (guint32 prefix)
{
	return prefix < 32 ? ~htonl(0xFFFFFFFF >> prefix) : 0xFFFFFFFF;
}

/****************************************************************/

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_LIBRESWAN_RIGHT,                      G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_LEFTID,                     G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_LEFTXAUTHUSER,              G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_DOMAIN,                     G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_DHGROUP,                    G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_PFSGROUP,                   G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_DPDTIMEOUT,                 G_TYPE_INT, 0, 86400 },
	{ NM_LIBRESWAN_IKE,                        G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_ESP,                        G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_VENDOR,                     G_TYPE_STRING, 0, 0 },
	/* Ignored option for internal use */
	{ NM_LIBRESWAN_PSK_INPUT_MODES,            G_TYPE_NONE, 0, 0 },
	{ NM_LIBRESWAN_XAUTH_PASSWORD_INPUT_MODES, G_TYPE_NONE, 0, 0 },
	{ NM_LIBRESWAN_PSK_VALUE "-flags",         G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_XAUTH_PASSWORD "-flags",    G_TYPE_STRING, 0, 0 },
	{ NULL,                                   G_TYPE_NONE, 0, 0 }
};

static ValidProperty valid_secrets[] = {
	{ NM_LIBRESWAN_PSK_VALUE,                  G_TYPE_STRING, 0, 0 },
	{ NM_LIBRESWAN_XAUTH_PASSWORD,             G_TYPE_STRING, 0, 0 },
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
nm_libreswan_properties_validate (NMSettingVpn *s_vpn, GError **error)
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
nm_libreswan_secrets_validate (NMSettingVpn *s_vpn, GError **error)
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

static void
block_quit (NMLibreswanPlugin *self)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	priv->quit_blockers++;
	_LOGD ("Block quit: %d blockers", priv->quit_blockers);
}

static void
unblock_quit (NMLibreswanPlugin *self)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	if (--priv->quit_blockers == 0)
		g_main_loop_quit (gl.loop);
	_LOGD ("Unblock quit: %d blockers", priv->quit_blockers);
}

/****************************************************************/

static gboolean connect_step (NMLibreswanPlugin *self, GError **error);
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
		"/usr/local/libexec/ipsec/",
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
	pipe->id = g_io_add_watch (pipe->channel, G_IO_IN | G_IO_ERR | G_IO_HUP, pr_cb, pipe);
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
connect_cleanup (NMLibreswanPlugin *self)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);

	priv->connect_step = CONNECT_STEP_FIRST;
	priv->pending_auth = FALSE;

	/* Don't remove the child watch since it needs to reap the child */
	priv->watch_id = 0;

	if (priv->pid) {
		kill (priv->pid, SIGTERM);
		priv->pid = 0;
	}

	if (priv->retry_id) {
		g_source_remove (priv->retry_id);
		priv->retry_id = 0;
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
delete_secrets_file (NMLibreswanPlugin *self)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);

	if (priv->secrets_path) {
		unlink (priv->secrets_path);
		g_clear_pointer (&priv->secrets_path, g_free);
	}
}

static void
connect_failed (NMLibreswanPlugin *self,
                GError *error,
                NMVpnPluginFailure reason)
{
	if (error) {
		_LOGW ("Connect failed: (%s/%d) %s",
		       g_quark_to_string (error->domain),
		       error->code,
		       error->message);
	}

	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (self), reason);
}

static void
check_running_cb (GPid pid, gint status, gpointer user_data)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (user_data);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
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

	_LOGD ("Spawn: child %d exited with status %d", pid, ret);
	unblock_quit (self);

	/* Reap child */
	waitpid (pid, NULL, WNOHANG);

	if (ret)
		priv->connect_step++;
	else
		priv->connect_step = CONNECT_STEP_WAIT_READY;

	if (!connect_step (self, &error))
		connect_failed (self, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	g_clear_error (&error);
}

static gboolean
retry_cb (gpointer user_data)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (user_data);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	GError *error = NULL;

	priv->retry_id = 0;

	if (!connect_step (self, &error))
		connect_failed (self, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	priv->retries--;
	g_clear_error (&error);

	return FALSE;
}

static void
child_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (user_data);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	guint ret = 1;
	GError *error = NULL;
	gboolean success;

	_LOGD ("Spawn: child %d exited", pid);
	unblock_quit (self);

	if (priv->watch_id == 0 || priv->pid != pid) {
		/* Reap old child */
		waitpid (pid, NULL, WNOHANG);
		return;
	}

	priv->watch_id = 0;
	priv->pid = 0;

	if (WIFEXITED (status)) {
		ret = WEXITSTATUS (status);
		if (ret)
			_LOGI ("Spawn: child %d exited with error code %d", pid, ret);
	} else
		_LOGW ("Spawn: child %d died unexpectedly", pid);

	/* Reap child */
	waitpid (pid, NULL, WNOHANG);

	if (priv->connect_step == CONNECT_STEP_FIRST) {
		nm_vpn_service_plugin_disconnect (self, NULL);
		return;
	}

	/* Ready step can return a failure even if libreswan is ready,
	 * but failed to listen to some interfaces due to a bug in older
	 * libreswan versions. */
	if (priv->connect_step == CONNECT_STEP_WAIT_READY)
		success = (ret != 1);
	else
		success = (ret == 0);

	/* Ignore failures here, maybe the libreswan daemon is too old. */
	if (priv->connect_step == CONNECT_STEP_CHECK_NSS)
		success = TRUE;

	if (success) {
		/* Success; do the next connect step */
		priv->connect_step++;
		priv->retries = 0;
		success = connect_step (self, &error);
	} else if (priv->retries) {
		_LOGI ("Spawn: %d more tries...", priv->retries);
		priv->retry_id = g_timeout_add (100, retry_cb, self);
		return;
	}

	if (!success)
		connect_failed (self, error, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	g_clear_error (&error);
}

static gboolean do_spawn (NMLibreswanPlugin *self,
                          GPid *out_pid,
                          int *out_stdin,
                          int *out_stderr,
                          GError **error,
                          const char *progname,
                          ...) G_GNUC_NULL_TERMINATED;

static gboolean
do_spawn (NMLibreswanPlugin *self,
          GPid *out_pid,
          int *out_stdin,
          int *out_stderr,
          GError **error,
          const char *progname,
          ...)
{
	GError *local = NULL;
	va_list ap;
	GPtrArray *argv;
	gs_free char *cmdline = NULL;
	char *arg;
	gboolean success;
	GPid pid = 0;

	argv = g_ptr_array_sized_new (10);
	g_ptr_array_add (argv, (char *) progname);

	va_start (ap, progname);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (argv, arg);
	va_end (ap);
	g_ptr_array_add (argv, NULL);

	_LOGI ("Spawn: %s", (cmdline = g_strjoinv (" ", (char **) argv->pdata)));

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
		_LOGD ("Spawn: child process %d", pid);
	} else {
		_LOGW ("Spawn failed: (%s/%d) %s",
		       g_quark_to_string (local->domain),
		       local->code, local->message);
		g_propagate_error (error, local);
	}

	if (out_pid)
		*out_pid = pid;

	g_ptr_array_free (argv, TRUE);
	if (success)
		block_quit (self);
	return success;
}

static gboolean
nm_libreswan_config_psk_write (NMSettingVpn *s_vpn,
                               const char *secrets_path,
                               GError **error)
{
	const char *pw_type, *psk, *leftid, *right;
	int fd;
	int errsv;
	gboolean success;

	/* Check for ignored group password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_PSK_INPUT_MODES);
	if (pw_type && !strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED))
		return TRUE;

	psk = nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_PSK_VALUE);
	if (!psk)
		return TRUE;

	/* Write the PSK */
	errno = 0;
	fd = open (secrets_path, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		errsv = errno;

		if (errsv == ENOENT) {
			gs_free char *dirname = g_path_get_dirname (secrets_path);

			if (!g_file_test (dirname, G_FILE_TEST_IS_DIR)) {
				g_set_error (error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
				             "Failed to open secrets file: no directory %s",
				             dirname);
				return FALSE;
			}
		}

		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "Failed to open secrets file: (%d) %s.",
		             errsv, g_strerror (errsv));
		return FALSE;
	}

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_LEFTID);
	if (leftid) {
		success = write_config_option (fd, NULL, error, "@%s: PSK \"%s\"", leftid, psk);
	} else {
		right = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_RIGHT);
		g_assert (right);
		success = write_config_option (fd, NULL, error, "%s %%any: PSK \"%s\"", right, psk);
	}

	if (!success) {
		g_close (fd, NULL);
		return FALSE;
	}
	return g_close (fd, error);
}

/****************************************************************/

static gboolean spawn_pty (NMLibreswanPlugin *self,
                           int *out_stdout,
                           int *out_stderr,
                           int *out_ptyin,
                           GPid *out_pid,
                           GError **error,
                           const char *progname,
                           ...) G_GNUC_NULL_TERMINATED;

static gboolean
spawn_pty (NMLibreswanPlugin *self,
           int *out_stdout,
           int *out_stderr,
           int *out_ptyin,
           GPid *out_pid,
           GError **error,
           const char *progname,
           ...)
{
	int pty_master_fd = 0;
	int stdout_pipe[2], stderr_pipe[2];
	pid_t child_pid;
	struct termios termios_flags;
	va_list ap;
	GPtrArray *argv;
	gs_free char *cmdline = NULL;
	char *arg;
	int ret;

	/* The pipes */
	if (pipe (stdout_pipe) == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: failed to create a stdout pipe (%d): %s",
		             errno, g_strerror (errno));
		return FALSE;
	}
	if (pipe (stderr_pipe) == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: failed to create a stderr pipe (%d): %s",
		             errno, g_strerror (errno));
		close (stdout_pipe[0]);
		close (stdout_pipe[1]);
		return FALSE;
	}

	/* Set the parent pipes non-blocking, so we can read big buffers
	 * in the callback without having to use FIONREAD
	 * to make sure the callback doesn't block.
	 */
	ret = fcntl (stdout_pipe[0], F_GETFL);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_GETFL on stdout failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stdout_pipe[0], F_SETFL, O_NONBLOCK | ret);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_SETFL on stdout failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stderr_pipe[0], F_GETFL);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_GETFL on stderr failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stderr_pipe[0], F_SETFL, O_NONBLOCK | ret);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_SETFL on stderr failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}

	/* Disable buffering of child writes */
	ret = fcntl (stdout_pipe[1], F_GETFL);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_GETFL on child stdout failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stdout_pipe[1], F_SETFL, O_SYNC | ret);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_SETFL on child stdout failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stderr_pipe[1], F_GETFL);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_GETFL on child stderr failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}
	ret = fcntl (stderr_pipe[1], F_SETFL, O_SYNC | ret);
	if (ret == -1) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "PTY spawn: F_SETFL on child stderr failed (%d): %s",
		             errno, g_strerror (errno));
		goto badpipes;
	}

	/* The command line arguments */
	argv = g_ptr_array_sized_new (10);
	g_ptr_array_add (argv, (char *) progname);

	va_start (ap, progname);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (argv, arg);
	va_end (ap);
	g_ptr_array_add (argv, NULL);

	_LOGI ("PTY spawn: %s", (cmdline = g_strjoinv (" ", (char **) argv->pdata)));

	/* Fork the command */
	child_pid = forkpty (&pty_master_fd, NULL, NULL, NULL);
	if (child_pid == 0) {
		/* in the child */

		if (dup2 (stdout_pipe[1], 1) == -1) {
			_LOGE ("PTY spawn: cannot dup stdout (%d): %s.", errno, g_strerror (errno));
			_exit (-1);
		}
		if (dup2 (stderr_pipe[1], 2) == -1) {
			_LOGE ("PTY spawn: cannot dup stderr (%d): %s.", errno, g_strerror (errno));
			_exit (-1);
		}

		/* Close unnecessary pipes */
		close (stderr_pipe[0]);
		close (stdout_pipe[0]);

		/* Ensure output is untranslated */
		setenv ("LC_ALL", "C", 1);
		setenv ("LANG", "C", 1);

		execv (argv->pdata[0], (char * const*) argv->pdata);

		/* This is probably a rather futile attempt to produce an error message
		 * as it goes to the piped stderr. */
		_LOGE ("PTY spawn: cannot exec '%s' (%d): %s", (char *) argv->pdata[0],
		         errno, g_strerror (errno));
		_exit (-1);
	}

	_LOGD ("PTY spawn: child process %d", child_pid);

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

	block_quit (self);
	return TRUE;

badpipes:
	close (stderr_pipe[0]);
	close (stdout_pipe[0]);
	close (stderr_pipe[1]);
	close (stdout_pipe[1]);
	return FALSE;
}

/****************************************************************/

/* The various SWANs don't tell helper scripts whether upstream sent
 * specific subnets to be routed over the VPN (eg, CISCO_SPLIT_INC).
 * This is what we need to automatically determine 'never-default' behavior.
 * Instead, we have to inspect the kernel's SAD (Security Assocation Database)
 * for IPSec-secured routes pointing to the VPN gateway.
 */

typedef struct {
	struct in_addr gw4;
	gboolean have_routes4;
} RoutesInfo;

static int
verify_source (struct nl_msg *msg, gpointer user_data)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid || creds->uid || creds->gid) {
		if (creds) {
			_LOGW ("netlink: received non-kernel message (pid %d uid %d gid %d)",
			       creds->pid, creds->uid, creds->gid);
		} else
			_LOGW ("netlink: received message without credentials");
		return NL_STOP;
	}

	return NL_OK;
}

static struct nl_sock *
setup_socket (void)
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc ();
	g_return_val_if_fail (sk, NULL);

	/* Only ever accept messages from kernel */
	err = nl_socket_modify_cb (sk, NL_CB_MSG_IN, NL_CB_CUSTOM, verify_source, NULL);
	g_assert (!err);

	err = nl_connect (sk, NETLINK_XFRM);
	g_assert (!err);
	err = nl_socket_set_passcred (sk, 1);
	g_assert (!err);

	return sk;
}

static int
parse_reply (struct nl_msg *msg, void *arg)
{
	RoutesInfo *info = arg;
	struct nlmsghdr *n = nlmsg_hdr (msg);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_userpolicy_info *xpinfo = NULL;

	if (info->have_routes4) {
		/* already found some routes */
		return NL_SKIP;
	}

	if (n->nlmsg_type != XFRM_MSG_NEWPOLICY) {
		_LOGW ("msg type %d not NEWPOLICY", n->nlmsg_type);
		return NL_SKIP;
	}

	/* Netlink message header is followed by 'struct xfrm_userpolicy_info' and
	 * then the attributes.
	 */

	if (!nlmsg_valid_hdr (n, sizeof (struct xfrm_userpolicy_info))) {
		_LOGW ("msg too short");
		return -NLE_MSG_TOOSHORT;
	}

	xpinfo = nlmsg_data (n);
	if (nla_parse (tb, XFRMA_MAX,
	               nlmsg_attrdata (n, sizeof (struct xfrm_userpolicy_info)),
	               nlmsg_attrlen (n, sizeof (struct xfrm_userpolicy_info)),
	               NULL) < 0) {
		_LOGW ("failed to parse attributes");
		return NL_SKIP;
	}

	if (tb[XFRMA_TMPL]) {
		int attrlen = nla_len (tb[XFRMA_TMPL]);
		struct xfrm_user_tmpl *list = nla_data (tb[XFRMA_TMPL]);
		int i;

		/* We only look for subnet route associations, eg where
		 * (sel->prefixlen_d > 0), and for those associations, we match
		 * the xfrm_user_tmpl's destination address against the PLUTO_PEER.
		 */
		if (xpinfo->sel.family == AF_INET && xpinfo->sel.prefixlen_d > 0) {
			for (i = 0; i < attrlen / sizeof (struct xfrm_user_tmpl); i++) {
				struct xfrm_user_tmpl *tmpl = &list[i];

				if (   tmpl->family == AF_INET
				    && memcmp (&tmpl->id.daddr, &info->gw4, sizeof (struct in_addr)) == 0) {
					info->have_routes4 = TRUE;
					break;
				}
			}
		}
	}

	return NL_OK;
}

static gboolean
have_sad_routes (const char *gw_addr4)
{
	RoutesInfo info = { { 0 }, FALSE };
	struct nl_sock *sk;
	int err;

	if (inet_pton (AF_INET, gw_addr4, &info.gw4) != 1)
		return FALSE;

	sk = setup_socket ();
	if (!sk)
		return FALSE;

	err = nl_send_simple (sk, XFRM_MSG_GETPOLICY, NLM_F_DUMP, NULL, 0);
	if (err < 0) {
		_LOGW ("Error sending: %d %s", err, nl_geterror (err));
		goto done;
	}

	nl_socket_modify_cb (sk, NL_CB_VALID, NL_CB_CUSTOM, parse_reply, &info);

	err = nl_recvmsgs_default (sk);
	if (err < 0) {
		_LOGW ("Error parsing: %d %s", err, nl_geterror (err));
		goto done;
	}

done:
	nl_socket_free (sk);
	return info.have_routes4;
}

/****************************************************************/

static GVariant *
str_to_gvariant (const char *str, gboolean try_convert)
{

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	return g_variant_new_string (str);
}

static GVariant *
addr4_to_gvariant (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (temp_addr.s_addr);
}

static GVariant *
netmask4_to_gvariant (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
}

static GVariant *
addr4_list_to_gvariant (const char *str)
{
	GVariantBuilder builder;
	char **split;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_ARRAY);

	for (i = 0; split[i]; i++) {
		struct in_addr addr;

		if (inet_pton (AF_INET, split[i], &addr) > 0) {
			g_variant_builder_add_value (&builder, g_variant_new_uint32 (addr.s_addr));
		} else {
			g_strfreev (split);
			g_variant_unref (g_variant_builder_end (&builder));
			return NULL;
		}
	}

	g_strfreev (split);

	return g_variant_builder_end (&builder);
}

static const gchar *
lookup_string (GVariant *dict, const gchar *key)
{
	const gchar *value = NULL;

	g_variant_lookup (dict, key, "&s", &value);
	return value;
}

static void
_take_route (GPtrArray *routes, GVariant *new, gboolean alive)
{
	guint32 network, network2, netmask;
	guint32 plen, plen2;
	guint i;

	if (!new)
		return;

	g_variant_get_child (new, 0, "u", &network);
	g_variant_get_child (new, 1, "u", &plen);

	netmask = nm_utils_ip4_prefix_to_netmask (plen);

	for (i = 0; i < routes->len; i++) {
		GVariant *r = routes->pdata[i];

		g_variant_get_child (r, 0, "u", &network2);
		g_variant_get_child (r, 1, "u", &plen2);

		if (   plen2 == plen
		    && ((network ^ network2) & netmask) == 0) {
			g_ptr_array_remove_index (routes, i);
			break;
		}
	}

	if (alive) {
		/* On new or update, we always add the new route to the end.
		 * For update, we basically move the route to the end. */
		g_ptr_array_add (routes, g_variant_ref_sink (new));
	} else
		g_variant_unref (new);
}

static void
handle_route (GPtrArray *routes, GVariant *env, gboolean alive)
{
	GVariantBuilder builder;
	const gchar *net, *mask, *next_hop, *my_sourceip;

	if (!lookup_string (env, "PLUTO_PEER_CLIENT"))
		return;

	net = lookup_string (env, "PLUTO_PEER_CLIENT_NET");
	mask = lookup_string (env, "PLUTO_PEER_CLIENT_MASK");
	next_hop = lookup_string (env, "PLUTO_NEXT_HOP");
	my_sourceip = lookup_string (env, "PLUTO_MY_SOURCEIP");

	if (!net || !mask || !next_hop || !my_sourceip)
		return;

	if (g_strcmp0 (net, "0.0.0.0") == 0 && g_strcmp0 (mask, "0")) {
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&builder, addr4_to_gvariant ("0.0.0.0"));
		g_variant_builder_add_value (&builder, netmask4_to_gvariant ("128.0.0.0"));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (next_hop));
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (0));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (my_sourceip));
		_take_route (routes, g_variant_builder_end (&builder), alive);

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&builder, addr4_to_gvariant ("128.0.0.0"));
		g_variant_builder_add_value (&builder, netmask4_to_gvariant ("128.0.0.0"));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (next_hop));
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (0));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (my_sourceip));
		_take_route (routes, g_variant_builder_end (&builder), alive);
	} else {
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (net));
		g_variant_builder_add_value (&builder, netmask4_to_gvariant (mask));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (next_hop));
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (0));
		g_variant_builder_add_value (&builder, addr4_to_gvariant (my_sourceip));
		_take_route (routes, g_variant_builder_end (&builder), alive);
	}
}

static gboolean
handle_callback (NMDBusLibreswanHelper *object,
                 GDBusMethodInvocation *invocation,
                 GVariant *env,
                 gpointer user_data)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (user_data);
	GVariantBuilder config;
	GVariantBuilder builder;
	GVariant *val;
	gboolean success = FALSE;
	guint i;
	const char *verb;

	_LOGI ("Configuration from the helper received.");

	verb = lookup_string (env, "PLUTO_VERB");
	if (!verb) {
		_LOGW ("PLUTO_VERB missing");
		goto out;
	}

	g_variant_builder_init (&config, G_VARIANT_TYPE_VARDICT);

	/* Right peer (or Gateway) */
	val = addr4_to_gvariant (lookup_string (env, "PLUTO_PEER"));
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY, val);
	else {
		_LOGW ("IPsec/Pluto Right Peer (VPN Gateway)");
		goto out;
	}

	/*
	 * Tunnel device
	 * Indicate that this plugin doesn't use tun/tap device
	 */
	val = g_variant_new_string (NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE);
	g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);

	/* IP address */
	val = addr4_to_gvariant (lookup_string (env, "PLUTO_MY_SOURCEIP"));
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else {
		_LOGW ("IP4 Address");
		goto out;
	}

	/* PTP address; PTP address == internal IP4 address */
	val = addr4_to_gvariant (lookup_string (env, "PLUTO_MY_SOURCEIP"));
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else {
		_LOGW ("IP4 PTP Address");
		goto out;
	}

	/* Netmask */
	val = g_variant_new_uint32 (32);
	g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);

	/* DNS */
	val = addr4_list_to_gvariant (lookup_string (env, "PLUTO_CISCO_DNS_INFO"));
	if (!val) {
		/* libreswan value */
		val = addr4_list_to_gvariant (lookup_string (env, "PLUTO_PEER_DNS_INFO"));
	}
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, val);


	/* Default domain */
	val = str_to_gvariant (lookup_string (env, "PLUTO_CISCO_DOMAIN_INFO"), TRUE);
	if (!val) {
		/* libreswan value */
		val = str_to_gvariant (lookup_string (env, "PLUTO_PEER_DOMAIN_INFO"), TRUE);
	}
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN, val);

	/* Banner */
	val = str_to_gvariant (lookup_string (env, "PLUTO_PEER_BANNER"), TRUE);
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_BANNER, val);


	val = addr4_to_gvariant (lookup_string (env, "PLUTO_NEXT_HOP"));
	if (val)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);

	/* This route */
	if (g_strcmp0 (verb, "route-client") == 0 || g_strcmp0 (verb, "route-host"))
		handle_route (priv->routes, env, TRUE);
	else if (g_strcmp0 (verb, "unroute-client") == 0 || g_strcmp0 (verb, "unroute-host"))
		handle_route (priv->routes, env, FALSE);

	/* Routes */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aau"));
	for (i = 0; i < priv->routes->len; i++)
		g_variant_builder_add_value (&builder, (GVariant *) priv->routes->pdata[i]);
	g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES,
	                       g_variant_builder_end (&builder));

	/* :( */
	if (have_sad_routes (lookup_string (env, "PLUTO_PEER")))
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, g_variant_new_boolean (TRUE));

	success = TRUE;

out:
	if (success) {
		nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (user_data),
		                                      g_variant_builder_end (&config));
	} else {
		connect_failed (NM_LIBRESWAN_PLUGIN (user_data), NULL,
		                NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	}

	nmdbus_libreswan_helper_complete_callback (object, invocation);
	return success;
}

/****************************************************************/

#define PASSPHRASE_REQUEST "Enter passphrase: "

static gboolean
handle_auth (NMLibreswanPlugin *self, const char **out_message, const char **out_hint)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
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
				_LOGW ("Failed to write password to ipsec: '%s'", error->message);
				g_clear_error (&error);
				return FALSE;
			}
			p += bytes_written;
		} while (*p);

		g_io_channel_write_chars (priv->channel, "\n", -1, NULL, NULL);
		g_io_channel_flush (priv->channel, NULL);

		_LOGD ("PTY: password written");

		/* Don't re-use the password */
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
		priv->password = NULL;
	} else {
		*out_hint = NM_LIBRESWAN_XAUTH_PASSWORD;
		*out_message = _("A password is required.");
	}

	return TRUE;
}

static gboolean
io_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (user_data);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	char buf[256];
	GIOStatus status;
	gsize bytes_read = 0;
	gboolean success = FALSE;
	NMVpnPluginFailure reason = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	const char *found;

	if (condition & G_IO_HUP) {
		_LOGD ("PTY disconnected");
		priv->io_id = 0;
		return G_SOURCE_REMOVE;
	}

	if (condition & G_IO_ERR) {
		_LOGW ("PTY spawn: pipe error!");
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

	_LOGD ("VPN request '%s'", priv->io_buf->str);

	found = strstr (priv->io_buf->str, PASSPHRASE_REQUEST);
	if (found) {
		const char *hints[2] = { NULL, NULL };
		const char *message = NULL;

		/* Erase everything up to and including the passphrase request */
		g_string_erase (priv->io_buf, 0, (found + strlen (PASSPHRASE_REQUEST)) - priv->io_buf->str);

		if (!handle_auth (self, &message, &hints[0])) {
			_LOGW ("Unhandled management socket request '%s'", buf);
			reason = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			goto done;
		}

		if (message) {
			/* Request new secrets if we need any */
			priv->pending_auth = TRUE;
			if (priv->interactive) {
				_LOGD ("Requesting new secrets: '%s' (%s)", message, hints[0]);
				nm_vpn_service_plugin_secrets_required (NM_VPN_SERVICE_PLUGIN (self), message, hints);
			} else {
				/* Interactive not allowed, can't ask for more secrets */
				_LOGW ("More secrets required but cannot ask interactively");
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
		connect_failed (self, NULL, reason);
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
		_LOGD ("PTY(%s) pipe error!", pipe->detail);
		pipe->id = 0;
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
			_LOGD ("PTY(%s): %s", pipe->detail, pipe->str->str);
		g_string_erase (pipe->str, 0, (nl - pipe->str->str) + 1);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
connect_step (NMLibreswanPlugin *self, GError **error)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	const char *uuid;
	int fd = -1, up_stdout = -1, up_stderr = -1, up_pty = -1;
	gboolean success = FALSE;

	g_warn_if_fail (priv->watch_id == 0);
	priv->watch_id = 0;
	g_warn_if_fail (priv->pid == 0);
	priv->pid = 0;

	_LOGD ("Connect: step %d", priv->connect_step);

	uuid = nm_connection_get_uuid (priv->connection);
	g_return_val_if_fail (uuid && *uuid, FALSE);

	switch (priv->connect_step) {
	case CONNECT_STEP_FIRST:
		/* fall through */
		priv->connect_step++;

	case CONNECT_STEP_CHECK_RUNNING:
		if (!do_spawn (self, &priv->pid, NULL, NULL, error, priv->ipsec_path, "auto", "--status", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, check_running_cb, self);
		return TRUE;

	case CONNECT_STEP_STACK_INIT:
		if (!priv->openswan) {
			const char *stackman_path;

			stackman_path = find_helper_libexec ("_stackmanager", error);
			if (!stackman_path)
				return FALSE;

			/* Ensure the right IPsec kernel stack is loaded */
			success = do_spawn (self, &priv->pid, NULL, NULL, error, stackman_path, "start", NULL);
			if (success)
				priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
			return success;
		}
		/* fall through */
		priv->connect_step++;

	case CONNECT_STEP_CHECK_NSS:
		/* Start the IPsec service */
		if (!priv->openswan) {
			success = do_spawn (self, &priv->pid, NULL, NULL, error,
			                    priv->ipsec_path, "--checknss", NULL);
			if (success)
				priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
			return success;
		}
		/* fall through */
		priv->connect_step++;

	case CONNECT_STEP_IPSEC_START:
		/* Start the IPsec service */
		if (priv->openswan)
			success = do_spawn (self, &priv->pid, NULL, NULL, error, priv->ipsec_path, "setup", "start", NULL);
		else {
			success = do_spawn (self, &priv->pid, NULL, NULL, error,
			                    priv->pluto_path, "--config", NM_IPSEC_CONF,
			                    NULL);
		}
		if (success) {
			priv->managed = TRUE;
			priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		}
		return success;

	case CONNECT_STEP_WAIT_READY:
		if (!priv->retries)
			priv->retries = 30;
		if (!do_spawn (self, &priv->pid, NULL, NULL, error, priv->ipsec_path, "auto", "--ready", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		return TRUE;

	case CONNECT_STEP_CONFIG_ADD: {
		gboolean trailing_newline;
		gs_free char *bus_name = NULL;
		gs_free char *ifupdown_script = NULL;

		if (!do_spawn (self, &priv->pid, &fd, NULL, error, priv->ipsec_path,
		               "auto", "--replace", "--config", "-", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		g_object_get (self, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, &bus_name, NULL);

		/* openswan requires a terminating \n (otherwise it segfaults) while
		 * libreswan fails parsing the configuration if you include the \n.
		 * WTF?
		 */
		trailing_newline = priv->openswan;

		ifupdown_script = g_strdup_printf ("\"%s %d %ld %s\"",
		                                   NM_LIBRESWAN_HELPER_PATH,
		                                   LOG_DEBUG,
		                                   (long) getpid (),
		                                   bus_name);

		if (!nm_libreswan_config_write (fd,
		                                priv->connection,
		                                uuid,
		                                ifupdown_script,
		                                priv->openswan,
		                                trailing_newline,
		                                _debug_write_option,
		                                error)) {
			g_close (fd, NULL);
			return FALSE;
		}
		return g_close (fd, error);
	}
	case CONNECT_STEP_CONNECT:
		g_assert (uuid);
		if (!spawn_pty (self, &up_stdout, &up_stderr, &up_pty, &priv->pid, error,
		                priv->ipsec_path, "auto", "--up", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);

		/* Wait for the password request */
		priv->io_buf = g_string_sized_new (128);
		priv->channel = g_io_channel_unix_new (up_pty);
		g_io_channel_set_encoding (priv->channel, NULL, NULL);
		g_io_channel_set_buffered (priv->channel, FALSE);
		priv->io_id = g_io_add_watch (priv->channel, G_IO_IN | G_IO_ERR | G_IO_HUP, io_cb, self);

		if (_LOGD_enabled ()) {
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
is_openswan (const char *path)
{
	const char *argv[] = { path, NULL };
	gboolean openswan = FALSE;
	char *output = NULL;

	if (g_spawn_sync (NULL, (char **) argv, NULL, 0, NULL, NULL, &output, NULL, NULL, NULL)) {
		openswan = output && strcasestr (output, " Openswan ");
		g_free (output);
	}
	return openswan;
}

static gboolean
_connect_common (NMVpnServicePlugin   *plugin,
                 NMConnection  *connection,
                 GVariant      *details,
                 GError       **error)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (plugin);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *con_name = nm_connection_get_uuid (connection);

	if (_LOGD_enabled ()) {
		_LOGD ("connection:");
		nm_connection_dump (connection);
	}

	priv->ipsec_path = find_helper_bin ("ipsec", error);
	if (!priv->ipsec_path)
		return FALSE;

	priv->openswan = is_openswan (priv->ipsec_path);
	if (!priv->openswan) {
		priv->pluto_path = find_helper_libexec ("pluto", error);
		if (!priv->pluto_path)
			return FALSE;
		priv->whack_path = find_helper_libexec ("whack", error);
		if (!priv->whack_path)
			return FALSE;
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	if (!nm_libreswan_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_libreswan_secrets_validate (s_vpn, error))
		return FALSE;

	if (priv->connect_step != CONNECT_STEP_FIRST) {
		g_set_error_literal (error,
			                 NM_VPN_PLUGIN_ERROR,
			                 NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			                 "Already connecting!");
		return FALSE;
	}

	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_XAUTH_PASSWORD));

	/* Write the IPsec secret (group password); *SWAN always requires this and
	 * doesn't ask for it interactively.
	 */
	priv->secrets_path = g_strdup_printf (NM_IPSEC_SECRETS_DIR"/ipsec-%s.secrets", con_name);
	if (!nm_libreswan_config_psk_write (s_vpn, priv->secrets_path, error))
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

	NM_LIBRESWAN_PLUGIN_GET_PRIVATE (plugin)->interactive = TRUE;
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

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_PSK_INPUT_MODES);
	if (!pw_type || strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_PSK_VALUE)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_XAUTH_PASSWORD_INPUT_MODES);
	if (!pw_type || strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_XAUTH_PASSWORD)) {
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
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (plugin);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
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

	_LOGD ("VPN received new secrets; sending to ipsec");

	g_free (priv->password);
	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_XAUTH_PASSWORD));

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
		_LOGD ("Requesting new secrets: '%s'", message);
		nm_vpn_service_plugin_secrets_required (plugin, message, hints);
	}

	return TRUE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **error)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (plugin);
	gboolean ret;

	g_ptr_array_set_size (priv->routes, 0);

	if (!priv->connection)
		return TRUE;

	connect_cleanup (plugin);
	delete_secrets_file (plugin);

	if (!priv->managed) {
                const char *uuid = nm_connection_get_uuid (priv->connection);
		ret = do_spawn (plugin, &priv->pid, NULL, NULL, error,
		                priv->ipsec_path, "auto", "--delete", uuid, NULL);
	} else if (priv->openswan) {
		ret = do_spawn (plugin, &priv->pid, NULL, NULL, error,
                                priv->ipsec_path, "setup", "stop", NULL);
	} else {
		ret = do_spawn (plugin, &priv->pid, NULL, NULL, error,
		                priv->whack_path, "--shutdown", NULL);
	}

	if (ret)
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, plugin);

	g_clear_object (&priv->connection);

	return ret;
}

static void
dispose (GObject *object)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (object);
	GDBusInterfaceSkeleton *skeleton = G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton);

	if (skeleton) {
		if (g_dbus_interface_skeleton_get_object_path (skeleton))
			g_dbus_interface_skeleton_unexport (skeleton);
		g_signal_handlers_disconnect_by_func (skeleton, handle_callback, object);
	}

	G_OBJECT_CLASS (nm_libreswan_plugin_parent_class)->dispose (object);
}

static void
nm_libreswan_plugin_init (NMLibreswanPlugin *plugin)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (plugin);

	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) g_variant_unref);
}

static void
finalize (GObject *object)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (object);

	delete_secrets_file (NM_LIBRESWAN_PLUGIN (object));
	connect_cleanup (NM_LIBRESWAN_PLUGIN (object));
	g_clear_object (&priv->connection);

	g_ptr_array_unref (priv->routes);

	G_OBJECT_CLASS (nm_libreswan_plugin_parent_class)->finalize (object);
}

static void
nm_libreswan_plugin_class_init (NMLibreswanPluginClass *libreswan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (libreswan_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (libreswan_class);

	g_type_class_add_private (object_class, sizeof (NMLibreswanPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
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
		g_main_loop_quit (gl.loop);
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
quit_mainloop (NMLibreswanPlugin *plugin, gpointer user_data)
{
	g_signal_handlers_disconnect_by_func (plugin, quit_mainloop, user_data);
	unblock_quit (plugin);
}

int
main (int argc, char *argv[])
{
	NMLibreswanPlugin *plugin;
	NMLibreswanPluginPrivate *priv;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	GDBusConnection *connection;
	GError *error = NULL;
	const gchar *bus_name = NM_DBUS_SERVICE_LIBRESWAN;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_LIBRESWAN_LOCALEDIR);
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

	if (getenv ("LIBRESWAN_DEBUG") || getenv ("IPSEC_DEBUG"))
		gl.debug = TRUE;

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG,
	                                             gl.debug ? LOG_INFO : LOG_NOTICE);

	_LOGD ("%s (version " DIST_VERSION ") starting...", argv[0]);

	plugin = g_initable_new (NM_TYPE_LIBRESWAN_PLUGIN, NULL, &error,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                         NULL);
	if (!plugin) {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
		exit (1);
	}

	connection = nm_vpn_service_plugin_get_connection (NM_VPN_SERVICE_PLUGIN (plugin)),
	priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (plugin);
	priv->dbus_skeleton = nmdbus_libreswan_helper_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
	                                       connection,
	                                       NM_DBUS_PATH_LIBRESWAN_HELPER,
	                                       &error)) {
		_LOGW ("Failed to export helper interface: %s", error->message);
		g_error_free (error);
		g_clear_object (&plugin);
		exit (1);
	}

	g_dbus_connection_register_object (connection, NM_VPN_DBUS_PLUGIN_PATH,
	                                   nmdbus_libreswan_helper_interface_info (),
	                                   NULL, NULL, NULL, NULL);

	g_signal_connect (priv->dbus_skeleton, "handle-callback", G_CALLBACK (handle_callback), plugin);

	gl.loop = g_main_loop_new (NULL, FALSE);

	block_quit (plugin);
	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), NULL);

	setup_signals ();
	g_main_loop_run (gl.loop);

	g_clear_pointer (&gl.loop, g_main_loop_unref);
	g_object_unref (plugin);

	exit (0);
}
