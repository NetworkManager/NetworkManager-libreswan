/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager-libreswan -- libreswan plugin for Network manager
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef __NM_SERVICE_DEFINES_H__
#define __NM_SERVICE_DEFINES_H__

#include <glib.h>
#include <glib-object.h>

#define NM_VPN_SERVICE_TYPE_LIBRESWAN "org.freedesktop.NetworkManager.libreswan"
#define NM_VPN_SERVICE_TYPE_OPENSWAN  "org.freedesktop.NetworkManager.openswan"

#define NM_DBUS_SERVICE_LIBRESWAN     "org.freedesktop.NetworkManager.libreswan"
#define NM_DBUS_INTERFACE_LIBRESWAN   "org.freedesktop.NetworkManager.libreswan"
#define NM_DBUS_PATH_LIBRESWAN        "/org/freedesktop/NetworkManager/libreswan"
#define NM_DBUS_PATH_LIBRESWAN_HELPER "/org/freedesktop/NetworkManager/libreswan/helper"

#define NM_LIBRESWAN_HELPER_PATH      LIBEXECDIR"/nm-libreswan-service-helper"

#define NM_LIBRESWAN_RIGHT  "right"
#define NM_LIBRESWAN_LEFTID "leftid"
#define NM_LIBRESWAN_PSK_VALUE "pskvalue"
#define NM_LIBRESWAN_PSK_INPUT_MODES "pskinputmodes"
#define NM_LIBRESWAN_LEFTXAUTHUSER "leftxauthusername"
#define NM_LIBRESWAN_XAUTH_PASSWORD "xauthpassword"
#define NM_LIBRESWAN_XAUTH_PASSWORD_INPUT_MODES "xauthpasswordinputmodes"
#define NM_LIBRESWAN_DOMAIN "Domain"
#define NM_LIBRESWAN_DHGROUP "dhgroup"
#define NM_LIBRESWAN_PFSGROUP "pfsgroup"
#define NM_LIBRESWAN_DPDTIMEOUT "dpdtimeout"
#define NM_LIBRESWAN_IKE  "ike"
#define NM_LIBRESWAN_ESP  "esp"
#define NM_LIBRESWAN_IKELIFETIME "ikelifetime"
#define NM_LIBRESWAN_SALIFETIME "salifetime"
#define NM_LIBRESWAN_VENDOR  "vendor"
#define NM_LIBRESWAN_REMOTENETWORK "rightsubnet"

#define NM_LIBRESWAN_PW_TYPE_SAVE   "save"
#define NM_LIBRESWAN_PW_TYPE_ASK    "ask"
#define NM_LIBRESWAN_PW_TYPE_UNUSED "unused"

#ifndef NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE
#define NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE "_none_"
#endif

#endif /* __NM_SERVICE_DEFINES_H__ */
