/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file iw.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the wireless interface utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <fnmatch.h>
#include <linux/netlink.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "log.h"
#include "utarray.h"
#include "iw.h"

static const UT_icd netiw_info_icd = {sizeof(netiw_info_t), NULL, NULL, NULL};

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
	"unspecified",
	"IBSS",
	"managed",
	"AP",
	"AP/VLAN",
	"WDS",
	"monitor",
	"mesh point",
	"P2P-client",
	"P2P-GO",
	"P2P-device",
	"outside context of a BSS",
	"NAN",
};

static void mac_addr_n2a(char *mac_addr, const unsigned char *arg)
{
	int i, l;

	l = 0;
	for (i = 0; i < ETH_ALEN ; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

static const char *iftype_name(enum nl80211_iftype iftype, char *modebuf)
{
	if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
		return ifmodes[iftype];
	sprintf(modebuf, "Unknown mode (%d)", iftype);
	return modebuf;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((unsigned char *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]), nla_len(tb[NLMSGERR_ATTR_MSG]));
		log_trace("kernel reports: %*s\n", len, (char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
	}

	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		log_err("Failed to allocate netlink socket");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		log_err("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_EXT_ACK, &err, sizeof(err));

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		log_err("nl80211 not found");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static int process_phy_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	struct nlattr *nl_mode;
	int rem_mode;
	bool *isvalid = (bool*)arg;
	char* capability;
	char *wiphy;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY_NAME])
		wiphy = nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]);
		log_debug("Using Wiphy %s", wiphy);

	if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
		char modebuf[100];
		nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES], rem_mode) {
			capability = (char *) iftype_name(nla_type(nl_mode), modebuf);
			log_trace("%s -> %s", wiphy, capability);
			if (!strcmp(capability, "AP/VLAN")) {
				*isvalid = true;
			}
		}
	}

	return NL_SKIP;
}

static int process_iface_handler(struct nl_msg *msg, void *arg)
{
	UT_array *arr = (UT_array *) arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	netiw_info_t element;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFNAME]) {
		strcpy(element.ifname, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));

		if (tb_msg[NL80211_ATTR_IFINDEX]) {
			element.ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
			log_trace("%s -> ifindex=%d", element.ifname, element.ifindex);
		}

		if (tb_msg[NL80211_ATTR_WDEV]) {
			element.wdev = nla_get_u64(tb_msg[NL80211_ATTR_WDEV]);
			log_trace("%s -> wdev=0x%llx", element.ifname, (unsigned long long)element.wdev);
		}

		if (tb_msg[NL80211_ATTR_MAC]) {
			char mac_addr[20];
			memcpy(element.addr, nla_data(tb_msg[NL80211_ATTR_MAC]), ETH_ALEN);
			mac_addr_n2a(mac_addr, element.addr);
			log_trace("%s -> addr=%s", element.ifname, mac_addr);
		}

		if (tb_msg[NL80211_ATTR_WIPHY]) {
			element.wiphy = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
			log_trace("%s -> wiphy=%d", element.ifname, element.wiphy);
		}

		utarray_push_back(arr, &element);
	}

	return NL_SKIP;
}

static int8_t nl_new(struct nl80211_state *nlstate, struct nl_cb **cb, struct nl_msg **msg, int *err)
{
	if (nl80211_init(nlstate)) {		
		return -1;
	}

	*msg = nlmsg_alloc();
	if (*msg == NULL) {
		log_trace("failed to allocate netlink message");
		nl_socket_free(nlstate->nl_sock);
		return 1;
	}

	*cb = nl_cb_alloc(NL_CB_TYPE);
	if (*cb ==  NULL) {
		log_trace("failed to allocate netlink callbacks\n");
		nlmsg_free(*msg);
		nl_socket_free(nlstate->nl_sock);
		return 1;
	}

	nl_cb_err(*cb, NL_CB_CUSTOM, error_handler, err);
	nl_cb_set(*cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, err);
	nl_cb_set(*cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, err);

	return 0;
}

bool iwace_isvlan(uint32_t wiphy)
{
	bool isvlan = false;
	int err = 1;
	struct nl_cb *cb;
	struct nl_msg *msg;
	struct nl80211_state nlstate;

	if (nl_new(&nlstate, &cb, &msg, &err) != 0)
		return false;

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, wiphy);

	if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0) {
		nl_cb_put(cb);
		nlmsg_free(msg);
		nl_socket_free(nlstate.nl_sock);
		return false;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, process_phy_handler, &isvlan);

	while (err > 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
	}

	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(nlstate.nl_sock);
	return isvlan;

 nla_put_failure:
	log_trace("NLA_PUT_U32 failed");
	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(nlstate.nl_sock);
	return false;
}

UT_array *get_netiw_info(void)
{
	int err = 1;
	struct nl80211_state nlstate;
	struct nl_cb *cb;
	struct nl_msg *msg;
	UT_array *arr = NULL;
	utarray_new(arr, &netiw_info_icd);

	if (nl_new(&nlstate, &cb, &msg, &err) != 0)
		return NULL;

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0);

	if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0) {
		nl_cb_put(cb);
		nlmsg_free(msg);
		nl_socket_free(nlstate.nl_sock);
		utarray_free(arr);
		return NULL;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, process_iface_handler, arr);

	while (err > 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
	}

	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(nlstate.nl_sock);
	return arr;

 nla_put_failure:
	log_trace("NLA_PUT_U32 failed");
	nl_cb_put(cb);
	nlmsg_free(msg);
	nl_socket_free(nlstate.nl_sock);
	utarray_free(arr);
	return NULL;
}

bool is_iw_vlan(const char *ap_interface)
{
  UT_array *netif_list = NULL;
  log_debug("Checking %s exists", ap_interface);
  if (!iface_exists(ap_interface)) {
    log_trace("WiFi interface %s doesn't exist", ap_interface);
    return false;
  }

  netif_list = get_netiw_info();

  if (netif_list == NULL) {
    log_trace("Couldn't list wifi interfaces");
    return false;
  }

  netiw_info_t *el;
  for (el = (netiw_info_t*) utarray_front(netif_list); el != NULL; el = (netiw_info_t *) utarray_next(netif_list, el)) {
    if (!strcmp(el->ifname, ap_interface)) {
      if (!iwace_isvlan(el->wiphy)) {
        log_trace("WiFi interface %s doesn't suport vlan tagging", ap_interface);
        utarray_free(netif_list);
        return false;
      } else {
        utarray_free(netif_list);
        return true;
      }
    }
  }

  utarray_free(netif_list);
  return false;
}
