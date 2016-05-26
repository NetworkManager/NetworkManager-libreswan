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

extern gboolean debug;

__attribute__((__format__ (__printf__, 3, 4)))
static inline void
write_config_option_newline (int fd, gboolean new_line, const char *format, ...)
{
	gs_free char *string = NULL;
	va_list args;
	gsize l;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	va_end (args);

	if (debug)
		g_print ("Config: %s\n", string);

	l = strlen (string);
	if (new_line) {
		gs_free char *s = string;

		string = g_new (char, l + 1 + 1);
		memcpy (string, s, l);
		string[l] = '\n';
		string[l + 1] = '\0';
		l++;
	}

	if (write (fd, string, l) <= 0)
		g_warning ("nm-libreswan: error in write_config_option");
}
#define write_config_option(fd, ...) write_config_option_newline((fd), TRUE, __VA_ARGS__)

void
nm_libreswan_config_write (gint fd,
                           NMConnection *connection,
                           const char *bus_name,
                           gboolean openswan);

#endif /* __UTILS_H__ */
