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
#include "nm-utils/nm-vpn-plugin-macros.h"

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

	char *ipsec_conf;

	gboolean openswan;
	gboolean interactive;
	gboolean pending_auth;
	gboolean managed;
	gboolean xauth_enabled;

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

/****************************************************************/

static gboolean pr_cb (GIOChannel *source, GIOCondition condition, gpointer user_data);

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

	if (priv->xauth_enabled) {
		if (priv->io_id) {
			g_source_remove (priv->io_id);
			priv->io_id = 0;
		}
		g_clear_pointer (&priv->channel, g_io_channel_unref);

		if (priv->io_buf) {
			g_string_free (priv->io_buf, TRUE);
			priv->io_buf = NULL;
		}
		if (priv->password) {
			memset (priv->password, 0, strlen (priv->password));
			g_free (priv->password);
			priv->password = NULL;
		}
	}
	pipe_cleanup (&priv->out);
	pipe_cleanup (&priv->err);
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

G_GNUC_NULL_TERMINATED
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
	char *cmdline = NULL;
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

	_LOGD ("spawn: %s", (cmdline = g_strjoinv (" ", (char **) argv->pdata)));
	g_clear_pointer (&cmdline, g_free);

	success = g_spawn_async_with_pipes (NULL, (char **) argv->pdata, NULL,
	                                    G_SPAWN_DO_NOT_REAP_CHILD,
	                                    NULL, NULL, &pid, out_stdin,
	                                    NULL, out_stderr, &local);

	if (success) {
		_LOGI ("spawn: success: %ld (%s)",
		       (long) pid,
		       (cmdline = g_strjoinv (" ", (char **) argv->pdata)));
	} else {
		_LOGW ("spawn: failed: %s (%s)",
		       local->message,
		       (cmdline = g_strjoinv (" ", (char **) argv->pdata)));
		g_propagate_error (error, local);
	}
	g_clear_pointer (&cmdline, g_free);

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
	gs_free const char *secrets = NULL;
	mode_t old_mask;
	gboolean res;

	/* Check for ignored group password */
	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_PSK_INPUT_MODES);
	if (pw_type && !strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED))
		return TRUE;

	psk = nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_KEY_PSK_VALUE);
	if (!psk)
		return TRUE;
	if (strchr (psk, '"') || strchr (psk, '\n')) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Invalid character in password."));
		return FALSE;
	}

	leftid = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTID);
	if (leftid) {
		/* nm_libreswan_get_ipsec_conf() in _connect_common should've checked these. */
		g_return_val_if_fail (strchr (leftid, '"') == NULL, FALSE);
		g_return_val_if_fail (strchr (leftid, '\n') == NULL, FALSE);
		secrets = g_strdup_printf ("%s: PSK \"%s\"", leftid, psk);
	} else {
		right = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHT);

		/* nm_libreswan_get_ipsec_conf() in _connect_common should've checked these. */
		g_return_val_if_fail (right != NULL, FALSE);
		g_return_val_if_fail (strchr (right, '"') == NULL, FALSE);
		g_return_val_if_fail (strchr (right, '\n') == NULL, FALSE);

		secrets = g_strdup_printf ("%s %%any: PSK \"%s\"", right, psk);
	}

	old_mask = umask (S_IRWXG | S_IRWXO);
	res = g_file_set_contents (secrets_path, secrets, -1, error);
	umask (old_mask);
	return res;
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
	int pty_controller_fd = 0;
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
	child_pid = forkpty (&pty_controller_fd, NULL, NULL, NULL);
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

	tcgetattr (pty_controller_fd, &termios_flags);
	cfmakeraw (&termios_flags);
	cfsetospeed (&termios_flags, __MAX_BAUD);
	tcsetattr (pty_controller_fd, TCSANOW, &termios_flags);

	if (out_stdout)
		*out_stdout = stdout_pipe[0];
	if (out_stderr)
		*out_stderr = stderr_pipe[0];
	if (out_ptyin)
		*out_ptyin = pty_controller_fd;
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
 * for IPsec-secured routes pointing to the VPN gateway.
 */

typedef struct {
	int gw_addr_family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} gw;
	gboolean have_routes4;
	gboolean have_routes6;
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
parse_reply (struct nl_msg *msg, RoutesInfo *info)
{
	struct nlmsghdr *n = nlmsg_hdr (msg);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_userpolicy_info *xpinfo = NULL;

	if (info->have_routes4 && info->have_routes6) {
		/* Already determined that there are routes for both IPv4 and IPv6 */
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

	if (!NM_IN_SET (xpinfo->sel.family, AF_INET, AF_INET6))
		return NL_SKIP;

	/* We only look for subnet route associations, eg where
	 * (sel->prefixlen_d > 0), and for those associations, we match
	 * the xfrm_user_tmpl's destination address against the PLUTO_PEER.
	 */
	if (xpinfo->sel.prefixlen_d == 0)
		return NL_SKIP;

	if (tb[XFRMA_TMPL]) {
		int attrlen = nla_len (tb[XFRMA_TMPL]);
		struct xfrm_user_tmpl *list = nla_data (tb[XFRMA_TMPL]);
		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];
		char gw[INET6_ADDRSTRLEN];
		int i;

		for (i = 0; i < attrlen / sizeof (struct xfrm_user_tmpl); i++) {
			struct xfrm_user_tmpl *tmpl = &list[i];

			if (!NM_IN_SET (tmpl->family, AF_INET, AF_INET6))
				continue;

			if (   tmpl->family == info->gw_addr_family
			    && memcmp (&tmpl->id.daddr, &info->gw, nm_utils_addr_family_to_size (tmpl->family)) == 0) {

				_LOGD("found SAD non-default route: src %s/%u dst %s/%u gw %s",
					   inet_ntop (xpinfo->sel.family, &xpinfo->sel.saddr, saddr, sizeof (saddr)),
					   xpinfo->sel.prefixlen_s,
					   inet_ntop( xpinfo->sel.family, &xpinfo->sel.daddr, daddr, sizeof (daddr)),
					   xpinfo->sel.prefixlen_d,
					   inet_ntop (tmpl->family, &tmpl->id.daddr, gw, sizeof (gw)));

				if (xpinfo->sel.family == AF_INET) {
					info->have_routes4 = TRUE;
				} else if (xpinfo->sel.family == AF_INET6) {
					info->have_routes6 = TRUE;
				}
			}
		}
	}

	return NL_OK;
}

static void
have_sad_routes (const char *gw, int gw_addr_family,
                 gboolean *have_routes4, gboolean *have_routes6)
{
	RoutesInfo info = { };
	struct nl_sock *sk;
	int err;

	*have_routes4 = FALSE;
	*have_routes6 = FALSE;

	info.gw_addr_family = gw_addr_family;

	if (inet_pton (gw_addr_family, gw, &info.gw) != 1)
		return;

	sk = setup_socket ();

	err = nl_send_simple (sk, XFRM_MSG_GETPOLICY, NLM_F_DUMP, NULL, 0);
	if (err < 0) {
		_LOGW ("Error sending XFRM request: %d %s", err, nl_geterror (err));
		goto done;
	}

	nl_socket_modify_cb (sk, NL_CB_VALID, NL_CB_CUSTOM,
	                     (nl_recvmsg_msg_cb_t) parse_reply,
	                     &info);

	err = nl_recvmsgs_default (sk);
	if (err < 0) {
		_LOGW ("Error parsing XFRM policies: %d %s", err, nl_geterror (err));
		goto done;
	}

done:
	*have_routes4 = info.have_routes4;
	*have_routes6 = info.have_routes6;

	nl_socket_free (sk);
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
addr_to_gvariant (const char *str, int addr_family)
{
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;

	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (addr_family, str, &addr) <= 0)
		return NULL;

	if (addr_family == AF_INET) {
		return g_variant_new_uint32 (addr.v4.s_addr);
	} else {
		return g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                  &addr,
		                                  sizeof (addr.v6),
		                                  1);
	}
}

static gboolean
netmask_to_prefixlen (const char *str, int addr_family, guint *plen)
{
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;

	if (!str || strlen (str) < 1)
		return FALSE;

	if (inet_pton (addr_family, str, &addr) <= 0)
		return FALSE;

	if (addr_family == AF_INET) {
		*plen = nm_utils_ip4_netmask_to_prefix (addr.v4.s_addr);
		return TRUE;
	} else {
		guint tot_zeros = 0;
		guint zeros;
		int i;

		for (i = 3; i >= 0; i--) {
			if (ntohl (addr.v6.s6_addr32[i]) == 0)
				zeros = 32;
			else
				zeros = __builtin_ctz (ntohl (addr.v6.s6_addr32[i]));

			tot_zeros += zeros;
			if (zeros != 32)
				break;
		}
		*plen = 128 - tot_zeros;
		return TRUE;
	}
}

static void
addr_list_to_gvariants (const char *str, const char *desc, GVariant **out4, GVariant **out6)
{
	nm_auto_strfreev char **split = NULL;
	nm_auto_unref_variant_builder GVariantBuilder *builder4 = NULL;
	nm_auto_unref_variant_builder GVariantBuilder *builder6 = NULL;
	GVariantBuilder **builder;
	guint i;

	*out4 = NULL;
	*out6 = NULL;

	if (!str || strlen (str) < 1)
		return;

	split = g_strsplit (str, " ", -1);
	if (g_strv_length (split) == 0)
		return;

	for (i = 0; split[i]; i++) {
		GVariant *variant;
		int addr_family;

		addr_family = strchr (split[i], ':') ? AF_INET6 : AF_INET;
		variant = addr_to_gvariant (split[i], addr_family);
		if (!variant) {
			_LOGW ("ignoring invalid address \"%s\" for %s", split[i], desc);
			continue;
		}

		builder = (addr_family == AF_INET) ? &builder4 : &builder6;
		if (!*builder)
			*builder = g_variant_builder_new (G_VARIANT_TYPE_ARRAY);
		g_variant_builder_add_value (*builder, variant);
	}

	if (builder4)
		*out4 = g_variant_builder_end (builder4);
	if (builder6)
		*out6 = g_variant_builder_end (builder6);

	return;
}

static const gchar *
lookup_string (GVariant *dict, const gchar *key)
{
	const gchar *value = NULL;

	g_variant_lookup (dict, key, "&s", &value);
	return value;
}

static void
take_route (GPtrArray *routes, NMIPRoute *route, gboolean alive)
{
	int family;
	int family2;
	const char *dest;
	const char *dest2;
	guint plen;
	guint plen2;
	guint i;

	if (!route)
		return;

	family = nm_ip_route_get_family (route);
	plen = nm_ip_route_get_prefix (route);
	dest = nm_ip_route_get_dest (route);

	/* Check for duplicates */
	for (i = 0; i < routes->len; i++) {
		family2 = nm_ip_route_get_family (routes->pdata[i]);
		plen2 = nm_ip_route_get_prefix (routes->pdata[i]);
		dest2 = nm_ip_route_get_dest (routes->pdata[i]);

		if (family == family2 && plen == plen2 && nm_streq (dest, dest2)) {
			g_ptr_array_remove_index (routes, i);
			break;
		}
	}

	if (alive) {
		/* On new or update, we always add the new route to the end.
		 * For update, we basically move the route to the end. */
		g_ptr_array_add (routes, route);
	} else {
		nm_ip_route_unref (route);
	}
}

static GVariant *
route_to_gvariant(NMIPRoute *route)
{
	const char *dest;
	guint plen;
	GVariant *variant;
	const char *next_hop;
	const char *src = NULL;

	dest     = nm_ip_route_get_dest (route);
	plen     = nm_ip_route_get_prefix (route);
	next_hop = nm_ip_route_get_next_hop (route);

	variant  = nm_ip_route_get_attribute (route, NM_IP_ROUTE_ATTRIBUTE_SRC);
	if (variant) {
		nm_assert (g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING));
		src = g_variant_get_string (variant, NULL);
	}

	if (nm_ip_route_get_family (route) == AF_INET) {
		GVariantBuilder builder;

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("au"));
		g_variant_builder_add_value (&builder, addr_to_gvariant (dest, AF_INET));
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (plen));
		g_variant_builder_add_value (&builder, addr_to_gvariant (next_hop ?: "0.0.0.0", AF_INET));
		g_variant_builder_add_value (&builder, g_variant_new_uint32 (0));
		if (src)
			g_variant_builder_add_value (&builder, addr_to_gvariant (src, AF_INET));
		return g_variant_builder_end (&builder);
	} else {
		gs_free GVariant **variants = g_new (GVariant *, 5);

		variants[0] = addr_to_gvariant (dest, AF_INET6);
		variants[1] = g_variant_new_uint32 (plen);
		variants[2] = addr_to_gvariant (next_hop ?: "::", AF_INET6);
		variants[3] = g_variant_new_uint32 (0);
		variants[4] = addr_to_gvariant (src ?: "::", AF_INET6);

		return g_variant_new_tuple (variants, 5);
	}
}

static NMIPRoute *
new_route(int         family,
          const char *dest,
          guint       prefix,
          const char *next_hop,
          const char *src)
{
	NMIPRoute *route;
	gs_free_error GError *error = NULL;

	route = nm_ip_route_new (family, dest, prefix, next_hop, 0, &error);
	if (!route) {
		_LOGW("Error creating route: dest %s, prefix %u, next_hop %s: %s",
		       dest, prefix, next_hop, error->message);
		return NULL;
	}

	if (src) {
		nm_ip_route_set_attribute (route, NM_IP_ROUTE_ATTRIBUTE_SRC, g_variant_new_string (src));
	}

	return route;
}

static void
handle_route (GPtrArray *routes, GVariant *env, const char *verb, gboolean is_xfrmi)
{
	gboolean alive;
	const char *net;
	const char *peer;
	const char *mask;
	const char *next_hop = NULL;
	const char *my_sourceip = NULL;
	int addr_family;
	NMIPRoute *route;
	guint plen;
	gs_free_error GError *error = NULL;

	if (g_str_has_prefix (verb, "route-"))
		alive = TRUE;
	else if (g_str_has_prefix (verb, "unroute-"))
		alive = FALSE;
	else {
		/* no route change */
		return;
	}

	peer = lookup_string (env, "PLUTO_PEER");
	net = lookup_string (env, "PLUTO_PEER_CLIENT_NET");
	mask = lookup_string (env, "PLUTO_PEER_CLIENT_MASK");
	my_sourceip = lookup_string (env, "PLUTO_MY_SOURCEIP");

	if (!peer || !net || !mask)
		return;

	if (!is_xfrmi) {
		next_hop = lookup_string (env, "PLUTO_NEXT_HOP");
		if (!next_hop)
			return;
	}

	/* Use the next hop only if it's not directly through the peer */
	if (nm_streq0 (peer, next_hop))
		next_hop = NULL;

	addr_family = strchr(net, ':') ? AF_INET6 : AF_INET;

	if (!netmask_to_prefixlen (mask, addr_family, &plen)) {
		_LOGW("Invalid route netmask: %s", mask);
		return;
	}

	if (addr_family == AF_INET && nm_streq (net, "0.0.0.0") && plen == 0) {
		/* We want to override the default route that might already exist
		 * on the interface. Split our default route into two /1 routes
		 * that will be preferred due to the longest prefix. */
		route = new_route (AF_INET, "0.0.0.0", 1, next_hop, my_sourceip);
		take_route (routes, route, alive);

		route = new_route (AF_INET, "128.0.0.0", 1, next_hop, my_sourceip);
		take_route (routes, route, alive);
	} else if (addr_family == AF_INET6 && nm_streq (net, "::") && plen == 0) {
		/* Do the same as Libreswan script /usr/libexec/ipsec/_updown.xfrm:
		 * add a route 2000::/3 that eclipses the default route without
		 * replacing it */
		route = new_route (AF_INET6, "2000::", 3, next_hop, my_sourceip);
		take_route (routes, route, alive);
	} else {
		/* Generic route */
		route = new_route (addr_family, net, plen, next_hop, my_sourceip);
		take_route (routes, route, alive);
	}
}

static gboolean
handle_callback (NMDBusLibreswanHelper *object,
                 GDBusMethodInvocation *invocation,
                 GVariant *env,
                 gpointer user_data)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (user_data);
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	nm_auto_clear_variant_builder GVariantBuilder config = {};
	nm_auto_clear_variant_builder GVariantBuilder ip4_config = {};
	nm_auto_clear_variant_builder GVariantBuilder ip6_config = {};
	GVariantBuilder *ip_config[2] = { &ip4_config, &ip6_config };
	gboolean has_ip_config[2] = { FALSE, FALSE };
	GVariant *variant;
	const char *xfrm_interface = NULL;
	const char *verb;
	gboolean success = FALSE;
	gboolean is_ipv6;
	gboolean dyn_addr_needed;
	const char *cstr;
	char *str = NULL;
	gs_free_error GError *local = NULL;

	verb = lookup_string (env, "PLUTO_VERB");
	if (!verb) {
		_LOGW ("PLUTO_VERB missing");
		goto out;
	}

	_LOGI ("Configuration from the helper received, verb '%s'", verb);

	g_variant_builder_init (&config, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip4_config, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip6_config, G_VARIANT_TYPE_VARDICT);

	/* address family for the tunnel. Note that VPN can support traffic of the other
	 * address family inside the tunnel, when the {left,right}subnets options specify
	 * the other family. */
	is_ipv6 = g_str_has_suffix (verb, "-v6");

	variant = str_to_gvariant (lookup_string (env, "PLUTO_PEER_BANNER"), TRUE);
	if (variant)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_BANNER, variant);

	variant = addr_to_gvariant (lookup_string (env, "PLUTO_PEER"), is_ipv6 ? AF_INET6 : AF_INET);
	if (variant)
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, variant);
	else {
		_LOGW ("IPsec/Pluto Right Peer (VPN Gateway) is missing or invalid");
		goto out;
	}

	if (nm_streq0 (lookup_string (env, "PLUTO_XFRMI_ROUTE"), "yes")) {
		/* Route-based VPN, configured via option "ipsec-interface". No
		 * next-hop is needed, the traffic is sent over the interface without
		 * a gateway */
		xfrm_interface = lookup_string (env, "PLUTO_VIRT_INTERFACE");
		variant = str_to_gvariant (xfrm_interface, TRUE);
		if (variant)
			g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, variant);
	} else {
		variant = addr_to_gvariant (lookup_string (env, "PLUTO_NEXT_HOP"), is_ipv6 ? AF_INET6 : AF_INET);
		if (variant) {
			g_variant_builder_add (&config, "{sv}",
			                       is_ipv6 ? NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY : NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY,
			                       variant);
		}
	}

	s_vpn = get_setting_vpn_sanitized (priv->connection, &local);
	if (!s_vpn) {
		_LOGW("%s", local->message);
		goto out;
	}

	dyn_addr_needed = _nm_utils_ascii_str_to_bool (
		nm_setting_vpn_get_data_item(s_vpn, NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT),
		FALSE);

	if (dyn_addr_needed) {
		/* IP address */
		variant = addr_to_gvariant (lookup_string (env, "PLUTO_MY_SOURCEIP"), is_ipv6 ? AF_INET6 : AF_INET);
		if (variant) {
			g_variant_builder_add (ip_config[is_ipv6], "{sv}",
			                       is_ipv6 ? NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS : NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
			                       variant);
			if (!is_ipv6) {
				/* no PTP is expressed as PTP == ADDRESS */
				g_variant_builder_add (ip_config[is_ipv6], "{sv}",
				                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
				                       variant);
			}
		} else {
			_LOGW ("IP Address is missing");
			goto out;
		}

		/* Netmask */
		variant = g_variant_new_uint32 (is_ipv6 ? 128 : 32);
		g_variant_builder_add (ip_config[is_ipv6], "{sv}",
		                       is_ipv6 ? NM_VPN_PLUGIN_IP6_CONFIG_PREFIX : NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
		                       variant);
		has_ip_config[is_ipv6] = TRUE;
	}

	/* DNS */
	cstr = lookup_string (env, "PLUTO_CISCO_DNS_INFO");
	if (!cstr)
		cstr = lookup_string (env, "PLUTO_PEER_DNS_INFO");
	if (cstr) {
		GVariant *dns4 = NULL;
		GVariant *dns6 = NULL;

		addr_list_to_gvariants (cstr, "DNS", &dns4, &dns6);
		if (dns4) {
			g_variant_builder_add (&ip4_config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, dns4);
			has_ip_config[0] = TRUE;
		}
		if (dns6) {
			g_variant_builder_add (&ip6_config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_DNS, dns6);
			has_ip_config[1] = TRUE;
		}
	}

	/* DNS domain */
	cstr = lookup_string (env, "PLUTO_CISCO_DOMAIN_INFO");
	if (!cstr)
		cstr = lookup_string (env, "PLUTO_PEER_DOMAIN_INFO");
	if (cstr && (has_ip_config[0] || has_ip_config[1])) {
		variant = str_to_gvariant (cstr, TRUE);
		if (variant) {
			g_variant_builder_add (has_ip_config[0] ? &ip4_config : &ip6_config, "{sv}",
			                       has_ip_config[0] ? NM_VPN_PLUGIN_IP4_CONFIG_DOMAIN : NM_VPN_PLUGIN_IP6_CONFIG_DOMAIN,
			                       variant);
		}
	}

	/* Routes */
	{
		nm_auto_unref_variant_builder GVariantBuilder *routes4 = NULL;
		nm_auto_unref_variant_builder GVariantBuilder *routes6 = NULL;
		guint i;

		handle_route (priv->routes, env, verb, !!xfrm_interface);

		for (i = 0; i < priv->routes->len; i++) {
			NMIPRoute *route = priv->routes->pdata[i];

			variant = route_to_gvariant (route);

			if (nm_ip_route_get_family (route) == AF_INET) {
				if (!routes4)
					routes4 = g_variant_builder_new (G_VARIANT_TYPE("aau"));
				g_variant_builder_add_value (routes4, variant);
			} else {
				if (!routes6)
					routes6 = g_variant_builder_new (G_VARIANT_TYPE ("a(ayuayuay)"));
				g_variant_builder_add_value (routes6, variant);
			}
		}

		if (routes4) {
			g_variant_builder_add (&ip4_config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ROUTES,
			                       g_variant_builder_end (routes4));
			has_ip_config[0] = TRUE;
		}
		if (routes6) {
			g_variant_builder_add (&ip6_config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ROUTES,
			                       g_variant_builder_end (routes6));
			has_ip_config[1] = TRUE;
		}
	}

	if (has_ip_config[0] || has_ip_config[1]) {
		gboolean have_routes4;
		gboolean have_routes6;

		/* Determine the never-default value based on the presence of SAD routes :( */

		have_sad_routes (lookup_string (env, "PLUTO_PEER"),
		                 is_ipv6 ? AF_INET6 : AF_INET,
		                 &have_routes4,
		                 &have_routes6);

		if (has_ip_config[0] && have_routes4) {
			g_variant_builder_add (&ip4_config, "{sv}",
			                       NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT,
			                       g_variant_new_boolean (TRUE));
		}
		if (has_ip_config[1] && have_routes6) {
			g_variant_builder_add (&ip6_config, "{sv}",
			                       NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT,
			                       g_variant_new_boolean (TRUE));
		}
	}

	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP4,
	                       g_variant_new_boolean (has_ip_config[0]));
	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP6,
	                       g_variant_new_boolean (has_ip_config[1]));

	/* Finally, send configs to NM */
	variant = g_variant_builder_end (&config);
	g_variant_ref_sink (variant);
	_LOGD("sending config: %s", (str = g_variant_print (variant, FALSE)));
	g_clear_pointer (&str, g_free);
	nm_vpn_service_plugin_set_config (NM_VPN_SERVICE_PLUGIN (user_data), variant);
	g_variant_unref (variant);

	if (has_ip_config[0]) {
		variant = g_variant_builder_end (&ip4_config);
		_LOGD("sending IP4 config: %s", (str = g_variant_print (variant, FALSE)));
		g_clear_pointer (&str, g_free);
		nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (user_data),
		                                      variant);
		g_variant_unref (variant);
	}
	if (has_ip_config[1]) {
		variant = g_variant_builder_end (&ip6_config);
		_LOGD("sending IP6 config: %s", (str = g_variant_print (variant, FALSE)));
		g_clear_pointer (&str, g_free);
		nm_vpn_service_plugin_set_ip6_config (NM_VPN_SERVICE_PLUGIN (user_data),
		                                      variant);
	}

	success = TRUE;
out:
	if (!success) {
		connect_failed (NM_LIBRESWAN_PLUGIN (user_data), NULL,
		                NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	}

	nmdbus_libreswan_helper_complete_callback (object, invocation);

	return TRUE;
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
		*out_hint = NM_LIBRESWAN_KEY_XAUTH_PASSWORD;
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
write_config (int fd,
              const char *string,
              GError **error)
{
	const char *p;
	gsize l;
	int errsv;
	gssize w;

	_LOGD ("Config %s", string);

	l = strlen (string);
	p = string;
	while (true) {
		w = write (fd, p, l);
		if (w == l)
			return TRUE;
		if (w > 0) {
			g_assert (w < l);
			p += w;
			l -= w;
			continue;
		}
		if (w == 0) {
			errsv = EIO;
			break;
		}
		errsv = errno;
		if (errsv == EINTR)
			continue;
		break;
	}
	g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR,
	             _("Error writing config: %s"), g_strerror (errsv));
	return FALSE;
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
		priv->connect_step++;
		/* fallthrough */

	case CONNECT_STEP_CHECK_RUNNING:
		if (!do_spawn (self, &priv->pid, NULL, NULL, error, priv->ipsec_path, "auto", "--status", NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, check_running_cb, self);
		return TRUE;

	case CONNECT_STEP_STACK_INIT:
		if (!priv->openswan) {
			const char *stackman_path;

			stackman_path = nm_libreswan_find_helper_libexec ("_stackmanager", error);
			if (!stackman_path)
				return FALSE;

			/* Ensure the right IPsec kernel stack is loaded */
			success = do_spawn (self, &priv->pid, NULL, NULL, error, stackman_path, "start", NULL);
			if (success)
				priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
			return success;
		}
		priv->connect_step++;
		/* fallthrough */

	case CONNECT_STEP_CHECK_NSS:
		/* Start the IPsec service */
		if (!priv->openswan) {
			success = do_spawn (self, &priv->pid, NULL, NULL, error,
			                    priv->ipsec_path, "--checknss", NULL);
			if (success)
				priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
			return success;
		}
		priv->connect_step++;
		/* fallthrough */

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

		if (!do_spawn (self, &priv->pid, &fd, NULL, error, priv->ipsec_path,
		               "auto", "--replace", "--config", "-", uuid, NULL))
			return FALSE;
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);
		if (!write_config (fd, priv->ipsec_conf, error)) {
			g_close (fd, NULL);
			return FALSE;
		}
		return g_close (fd, error);
	}
	case CONNECT_STEP_CONNECT:
		g_assert (uuid);

		if (!spawn_pty (self, &up_stdout, &up_stderr,
		                priv->xauth_enabled ? &up_pty : NULL,
		                &priv->pid, error,
		                priv->ipsec_path, "auto", "--up", uuid, NULL)) {
			return FALSE;
		}
		priv->watch_id = g_child_watch_add (priv->pid, child_watch_cb, self);

		if (priv->xauth_enabled) {
			/* Wait for the password request */
			priv->io_buf = g_string_sized_new (128);
			priv->channel = g_io_channel_unix_new (up_pty);
			g_io_channel_set_encoding (priv->channel, NULL, NULL);
			g_io_channel_set_buffered (priv->channel, FALSE);
			priv->io_id = g_io_add_watch (priv->channel, G_IO_IN | G_IO_ERR | G_IO_HUP, io_cb, self);
		}
		pipe_init (&priv->out, up_stdout, "OUT");
		pipe_init (&priv->err, up_stderr, "ERR");
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
_connect_common (NMVpnServicePlugin   *plugin,
                 NMConnection  *connection,
                 GVariant      *details,
                 GError       **error)
{
	NMLibreswanPlugin *self = NM_LIBRESWAN_PLUGIN (plugin);
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (self);
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	const char *con_name = nm_connection_get_uuid (connection);
	gs_free char *ipsec_banner = NULL;
	gs_free char *ifupdown_script = NULL;
	gs_free char *bus_name = NULL;
	gboolean trailing_newline;
	int version;

	if (_LOGD_enabled ()) {
		_LOGD ("connection:");
		nm_connection_dump (connection);
	}

	if (priv->connect_step != CONNECT_STEP_FIRST) {
		g_set_error_literal (error,
			                 NM_VPN_PLUGIN_ERROR,
			                 NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			                 "Already connecting!");
		return FALSE;
	}

	priv->ipsec_path = nm_libreswan_find_helper_bin ("ipsec", error);
	if (!priv->ipsec_path)
		return FALSE;

	nm_libreswan_detect_version (priv->ipsec_path, &priv->openswan, &version, &ipsec_banner);
	_LOGD ("ipsec: version banner: %s", ipsec_banner);
	_LOGD ("ipsec: detected version %d (%s)", version, priv->openswan ? "Openswan" : "Libreswan");

	if (!priv->openswan) {
		priv->pluto_path = nm_libreswan_find_helper_libexec ("pluto", error);
		if (!priv->pluto_path)
			return FALSE;
		priv->whack_path = nm_libreswan_find_helper_libexec ("whack", error);
		if (!priv->whack_path)
			return FALSE;
	}

	s_vpn = get_setting_vpn_sanitized (connection, error);
	if (!s_vpn)
		return FALSE;

	g_object_get (self, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, &bus_name, NULL);

	ifupdown_script = g_strdup_printf ("%s %d %ld %s",
					   NM_LIBRESWAN_HELPER_PATH,
					   LOG_DEBUG,
					   (long) getpid (),
					   bus_name);

	/* openswan requires a terminating \n (otherwise it segfaults) while
	 * libreswan fails parsing the configuration if you include the \n.
	 * WTF?
	 */
	trailing_newline = priv->openswan;

	/* Compose the ipsec.conf early, to catch configuration errors before
	 * we initiate the conneciton. */
	priv->ipsec_conf = nm_libreswan_get_ipsec_conf (version,
		                                        s_vpn,
		                                        con_name,
		                                        ifupdown_script,
		                                        priv->openswan,
		                                        trailing_newline,
		                                        error);
	if (priv->ipsec_conf == NULL)
		return FALSE;

	/* XAUTH is not part of the IKEv2 standard and we always enforce it in IKEv1 */
	priv->xauth_enabled = !nm_libreswan_utils_setting_is_ikev2 (s_vpn);

	if (priv->xauth_enabled)
		priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_KEY_XAUTH_PASSWORD));

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
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	const char *leftcert;
	const char *leftrsasigkey;
	const char *rightcert;
	const char *rightrsasigkey;
	const char *pw_type;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = get_setting_vpn_sanitized (connection, error);
	if (!s_vpn)
		return FALSE;

	/* When leftcert is specified, rsasigkey are assumed to be '%cert' */
	leftcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTCERT);
	if (leftcert)
		goto xauth_check;

	/* If authentication is done through rsasigkeys, only the public keys are required.
	 * If rightcert is specified, rightrsasigkey is assumed to be '%cert' */
	leftrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_LEFTRSASIGKEY);
	rightrsasigkey = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTRSASIGKEY);
	rightcert = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_RIGHTCERT);
	if (leftrsasigkey && (rightrsasigkey || rightcert))
		goto xauth_check;

	pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_PSK_INPUT_MODES);
	if (!pw_type || strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED)) {
		if (!nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_KEY_PSK_VALUE)) {
			*setting_name = NM_SETTING_VPN_SETTING_NAME;
			return TRUE;
		}
	}

xauth_check:
	if (!nm_libreswan_utils_setting_is_ikev2 (s_vpn)) {
		pw_type = nm_setting_vpn_get_data_item (s_vpn, NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES);
		if (!pw_type || strcmp (pw_type, NM_LIBRESWAN_PW_TYPE_UNUSED)) {
			if (!nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_KEY_XAUTH_PASSWORD)) {
				*setting_name = NM_SETTING_VPN_SETTING_NAME;
				return TRUE;
			}
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
	gs_unref_object NMSettingVpn *s_vpn = NULL;
	const char *message = NULL;
	const char *hints[] = { NULL, NULL };

	s_vpn = get_setting_vpn_sanitized (connection, error);
	if (!s_vpn)
		return FALSE;

	_LOGD ("VPN received new secrets; sending to ipsec");

	g_free (priv->password);
	priv->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_LIBRESWAN_KEY_XAUTH_PASSWORD));

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
	g_clear_pointer (&priv->ipsec_conf, g_free);

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

	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);
}

static void
finalize (GObject *object)
{
	NMLibreswanPluginPrivate *priv = NM_LIBRESWAN_PLUGIN_GET_PRIVATE (object);

	g_clear_pointer (&priv->ipsec_conf, g_free);
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
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
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
