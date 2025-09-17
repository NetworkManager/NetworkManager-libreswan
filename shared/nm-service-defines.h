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

#define NM_LIBRESWAN_KEY_RIGHT                      "right"
#define NM_LIBRESWAN_KEY_RIGHTID                    "rightid"
#define NM_LIBRESWAN_KEY_RIGHTRSASIGKEY             "rightrsasigkey"
#define NM_LIBRESWAN_KEY_RIGHTCERT                  "rightcert"
#define NM_LIBRESWAN_KEY_LEFT                       "left"
#define NM_LIBRESWAN_KEY_LEFTID                     "leftid"
#define NM_LIBRESWAN_KEY_LEFTRSASIGKEY              "leftrsasigkey"
#define NM_LIBRESWAN_KEY_LEFTCERT                   "leftcert"
#define NM_LIBRESWAN_KEY_LEFTMODECFGCLIENT          "leftmodecfgclient"
#define NM_LIBRESWAN_KEY_AUTHBY                     "authby"
#define NM_LIBRESWAN_KEY_PSK_VALUE                  "pskvalue"
#define NM_LIBRESWAN_KEY_PSK_INPUT_MODES            "pskinputmodes"
#define NM_LIBRESWAN_KEY_LEFTXAUTHUSER              "leftxauthusername"
#define NM_LIBRESWAN_KEY_LEFTUSERNAME               "leftusername"
#define NM_LIBRESWAN_KEY_XAUTH_PASSWORD             "xauthpassword"
#define NM_LIBRESWAN_KEY_XAUTH_PASSWORD_INPUT_MODES "xauthpasswordinputmodes"
#define NM_LIBRESWAN_KEY_DOMAIN                     "Domain"
#define NM_LIBRESWAN_KEY_DHGROUP                    "dhgroup"
#define NM_LIBRESWAN_KEY_PFS                        "pfs"
#define NM_LIBRESWAN_KEY_PFSGROUP                   "pfsgroup"
#define NM_LIBRESWAN_KEY_DPDTIMEOUT                 "dpdtimeout"
#define NM_LIBRESWAN_KEY_DPDDELAY                   "dpddelay"
#define NM_LIBRESWAN_KEY_DPDACTION                  "dpdaction"
#define NM_LIBRESWAN_KEY_IKE                        "ike"
#define NM_LIBRESWAN_KEY_ESP                        "esp"
#define NM_LIBRESWAN_KEY_IKELIFETIME                "ikelifetime"
#define NM_LIBRESWAN_KEY_SALIFETIME                 "salifetime"
#define NM_LIBRESWAN_KEY_VENDOR                     "vendor"
#define NM_LIBRESWAN_KEY_RIGHTSUBNET                "rightsubnet"
#define NM_LIBRESWAN_KEY_RIGHTSUBNETS               "rightsubnets"
#define NM_LIBRESWAN_KEY_LEFTSUBNET                 "leftsubnet"
#define NM_LIBRESWAN_KEY_LEFTSUBNETS                "leftsubnets"
#define NM_LIBRESWAN_KEY_IKEV2                      "ikev2"
#define NM_LIBRESWAN_KEY_NARROWING                  "narrowing"
#define NM_LIBRESWAN_KEY_REKEY                      "rekey"
#define NM_LIBRESWAN_KEY_FRAGMENTATION              "fragmentation"
#define NM_LIBRESWAN_KEY_MOBIKE                     "mobike"
#define NM_LIBRESWAN_KEY_IPSEC_INTERFACE            "ipsec-interface"
#define NM_LIBRESWAN_KEY_TYPE                       "type"
#define NM_LIBRESWAN_KEY_HOSTADDRFAMILY             "hostaddrfamily"
#define NM_LIBRESWAN_KEY_CLIENTADDRFAMILY           "clientaddrfamily"
#define NM_LIBRESWAN_KEY_REQUIRE_ID_ON_CERTIFICATE  "require-id-on-certificate"
#define NM_LIBRESWAN_KEY_NM_AUTO_DEFAULTS           "nm-auto-defaults"
#define NM_LIBRESWAN_KEY_LEFTSENDCERT               "leftsendcert"
#define NM_LIBRESWAN_KEY_RIGHTCA                    "rightca"

#define NM_LIBRESWAN_IKEV2_NO      "no"
#define NM_LIBRESWAN_IKEV2_NEVER   "never"
#define NM_LIBRESWAN_IKEV2_YES     "yes"
#define NM_LIBRESWAN_IKEV2_PROPOSE "propose"
#define NM_LIBRESWAN_IKEV2_INSIST  "insist"

#define NM_LIBRESWAN_PW_TYPE_SAVE   "save"
#define NM_LIBRESWAN_PW_TYPE_ASK    "ask"
#define NM_LIBRESWAN_PW_TYPE_UNUSED "unused"

#define NM_LIBRESWAN_AGGRMODE_DEFAULT_IKE   "aes256-sha1;modp1536"
#define NM_LIBRESWAN_AGGRMODE_DEFAULT_ESP   "aes256-sha1"
#define NM_LIBRESWAN_IKEV1_DEFAULT_LIFETIME "24h"

#ifndef NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE
#define NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV_NONE "_none_"
#endif

#endif /* __NM_SERVICE_DEFINES_H__ */
