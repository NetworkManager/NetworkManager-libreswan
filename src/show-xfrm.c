/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define _LINUX_IN6_H 1
#include <linux/xfrm.h>

static int
verify_source (struct nl_msg *msg, gpointer user_data)
{
	struct ucred *creds = nlmsg_get_creds (msg);

	if (!creds || creds->pid || creds->uid || creds->gid) {
		if (creds)
			g_warning ("netlink: received non-kernel message (pid %d uid %d gid %d)",
			           creds->pid, creds->uid, creds->gid);
		else
			g_warning ("netlink: received message without credentials");
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

static void
xfrm_selector_print (struct xfrm_selector *sel)
{
	char buf[INET6_ADDRSTRLEN];

	if (sel->family == AF_INET || sel->family == AF_INET6) {
		inet_ntop (sel->family, &sel->saddr, buf, sizeof (buf));
		g_print ("src %s/%u ", buf, sel->prefixlen_s);

		inet_ntop (sel->family, &sel->daddr, buf, sizeof (buf));
		g_print ("dst %s/%u ", buf, sel->prefixlen_d);

		if (sel->ifindex > 0)
			g_print ("ifindex %d ", sel->ifindex);
		g_print ("\n");
	}
}

static int
parse_reply (struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *n = nlmsg_hdr (msg);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_userpolicy_info *xpinfo = NULL;

	if (n->nlmsg_type != XFRM_MSG_NEWPOLICY) {
		g_warning ("msg type %d not NEWPOLICY", n->nlmsg_type);
		return NL_SKIP;
	}

	/* Netlink message header is followed by 'struct xfrm_userpolicy_info' and
	 * then the attributes.
	 */

	if (!nlmsg_valid_hdr (n, sizeof (struct xfrm_userpolicy_info))) {
		g_warning ("msg too short");
		return -NLE_MSG_TOOSHORT;
	}

	xpinfo = nlmsg_data (n);
	if (nla_parse (tb, XFRMA_MAX,
	               nlmsg_attrdata (n, sizeof (struct xfrm_userpolicy_info)),
	               nlmsg_attrlen (n, sizeof (struct xfrm_userpolicy_info)),
	               NULL) < 0) {
		g_warning ("failed to parse attributes");
		return NL_SKIP;
	}

	if (tb[XFRMA_TMPL]) {
		int attrlen = nla_len (tb[XFRMA_TMPL]);
		struct xfrm_user_tmpl *list = nla_data (tb[XFRMA_TMPL]);
		int i;

		xfrm_selector_print (&xpinfo->sel);

		for (i = 0; i < attrlen / sizeof (struct xfrm_user_tmpl); i++) {
			struct xfrm_user_tmpl *tmpl = &list[i];
			char buf[INET6_ADDRSTRLEN];

			g_print ("    tmpl ");

			inet_ntop (tmpl->family, (gpointer) &tmpl->saddr, buf, sizeof (buf));
			g_print ("src %s ", buf);

			inet_ntop (tmpl->family, &tmpl->id.daddr, buf, sizeof (buf));
			g_print ("dst %s\n", buf);
		}
	}

	return NL_OK;
}


int main (int argc, char **argv)
{
	struct nl_sock *sk;
	int err;

	sk = setup_socket ();
	g_assert (sk);

	err = nl_send_simple (sk, XFRM_MSG_GETPOLICY, NLM_F_DUMP, NULL, 0);
	if (err < 0) {
		g_warning ("Error sending: %d %s", err, nl_geterror (err));
		return 1;
	}

	nl_socket_modify_cb (sk, NL_CB_VALID, NL_CB_CUSTOM, parse_reply, NULL);

	err = nl_recvmsgs_default (sk);
	if (err < 0) {
		g_warning ("Error parsing: %d %s", err, nl_geterror (err));
		return 1;
	}

	return 0;
}
