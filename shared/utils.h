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

#ifndef __UTILS_H__
#define __UTILS_H__

#include <errno.h>

typedef void (*NMDebugWriteFcn) (const char *setting);

__attribute__((__format__ (__printf__, 5, 6)))
static inline gboolean
write_config_option_newline (int fd, gboolean new_line, NMDebugWriteFcn debug_write_fcn, GError **error, const char *format, ...)
{
	gs_free char *string = NULL;
	const char *p;
	va_list args;
	gsize l;
	int errsv;
	gssize w;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	va_end (args);

	if (debug_write_fcn)
		debug_write_fcn (string);

	l = strlen (string);
	if (new_line) {
		gs_free char *s = string;

		string = g_new (char, l + 1 + 1);
		memcpy (string, s, l);
		string[l] = '\n';
		string[l + 1] = '\0';
		l++;
	}

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
			errno = EIO;
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
#define write_config_option(fd, debug_write_fcn, error, ...) write_config_option_newline((fd), TRUE, debug_write_fcn, error, __VA_ARGS__)

gboolean
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *bus_name,
                           gboolean openswan,
                           NMDebugWriteFcn debug_write_fcn,
                           GError **error);

#endif /* __UTILS_H__ */
