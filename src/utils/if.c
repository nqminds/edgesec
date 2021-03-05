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
 * @file if.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the network interface utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

#include "libnetlink.h"
#include "ll_map.h"
#include "utils.h"
#include "linux/if_addr.h"
#include "linux/if_arp.h"
#include "linux/if_infiniband.h"
#include "rt_names.h"

#include "nl80211.h"
#include "os.h"
#include "log.h"
#include "if.h"
#include "utarray.h"
// #include "uthash.h"

static int ifindex = 0;
struct rtnl_handle rth = { .fd = -1 };
static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};
static int have_rtnl_newlink = -1;

bool iface_exists(const char *ifname)
{
	if (ifname == NULL) {
		log_trace("ifname param is NULL");
		return false;
	}

	unsigned int idx = if_nametoindex(ifname);
	if (!idx) {
		return false;
	}

	return true;
}


static int store_nlmsg(struct nlmsghdr *n, void *arg)
{
	struct nlmsg_chain *lchain = (struct nlmsg_chain *) arg;
	struct nlmsg_list *h;

	h = os_malloc(n->nlmsg_len+sizeof(void *));
	if (h == NULL)
		return -1;

	memcpy(&h->h, n, n->nlmsg_len);
	h->next = NULL;

	if (lchain->tail)
		lchain->tail->next = h;
	else
		lchain->head = h;
	lchain->tail = h;

	ll_remember_index(n, NULL);
	return 0;
}

void free_nlmsg_chain(struct nlmsg_chain *info)
{
	struct nlmsg_list *l, *n;

	for (l = info->head; l; l = n) {
		n = l->next;
		os_free(l);
	}
}

/* fills in linfo with link data and optionally ainfo with address info
 * caller can walk lists as desired and must call free_nlmsg_chain for
 * both when done
 */
int ip_link_list(req_filter_fn_t filter_fn, struct nlmsg_chain *linfo)
{
	if (rtnl_linkdump_req_filter_fn(&rth, 0, filter_fn) < 0) {
		log_err("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, linfo) < 0) {
		log_trace("Dump terminated");
		return 1;
	}

	return 0;
}

static int iplink_filter_req(struct nlmsghdr *nlh, int reqlen)
{
	int err;

	err = addattr32(nlh, reqlen, IFLA_EXT_MASK, RTEXT_FILTER_VF);
	if (err)
		return err;

	return 0;
}

static int ipaddr_dump_filter(struct nlmsghdr *nlh, int reqlen)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(nlh);

	ifa->ifa_index = ifindex;

	return 0;
}

static int ip_addr_list(struct nlmsg_chain *ainfo, int if_id)
{
	ifindex = if_id;

	if (rtnl_addrdump_req(&rth, 0, ipaddr_dump_filter) < 0) {
		log_err("Cannot send dump request");
		return 1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, ainfo) < 0) {
		log_trace("Dump terminated");
		return 1;
	}

	return 0;
}

static void ipaddr_filter(struct nlmsg_chain *linfo, struct nlmsg_chain *ainfo)
{
	struct nlmsg_list *l, **lp;

	lp = &linfo->head;
	while ((l = *lp) != NULL) {
		int ok = 0;
		int missing_net_address = 1;
		struct ifinfomsg *ifi = NLMSG_DATA(&l->h);
		struct nlmsg_list *a;

		for (a = ainfo->head; a; a = a->next) {
			struct nlmsghdr *n = &a->h;
			struct ifaddrmsg *ifa = NLMSG_DATA(n);

			if (ifa->ifa_index != ifi->ifi_index)
				continue;
			ok = 1;
			break;
		}
		if (missing_net_address)
			ok = 1;
		if (!ok) {
			*lp = l->next;
			os_free(l);
		} else
			lp = &l->next;
	}
}

enum IF_STATE get_operstate(__u8 state)
{
	if (state >= 7) {
		return IF_STATE_OTHER;
	} else {
		return (enum IF_STATE) state; 
	}
}

int get_addrinfo(struct nlmsghdr *n, netif_info_t *info)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *rta_tb[IFA_MAX+1];

	SPRINT_BUF(b1);

	if (n->nlmsg_type != RTM_NEWADDR && n->nlmsg_type != RTM_DELADDR)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		log_trace("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	if (!rta_tb[IFA_LOCAL])
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
	if (!rta_tb[IFA_ADDRESS])
		rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

	if (ifindex && ifindex != ifa->ifa_index)
		return 0;

	info->ifa_family = ifa->ifa_family;
	const char *name = family_name(ifa->ifa_family);
	
	if (*name != '?') {
		log_trace("ifindex=%d family=%s", info->ifindex, name);
	} else {
		log_trace("ifindex=%d family_index=%d", info->ifindex, info->ifa_family);
	}

	if (rta_tb[IFA_LOCAL] && info->ifa_family == AF_INET) {
		strcpy(info->ip_addr, format_host_rta(ifa->ifa_family, rta_tb[IFA_LOCAL]));
		log_trace("ifindex=%d ip_addr=%s", info->ifindex, info->ip_addr);
		if (rta_tb[IFA_ADDRESS] && memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]), RTA_DATA(rta_tb[IFA_LOCAL]), 4)) {
			strcpy(info->peer_addr, format_host_rta(ifa->ifa_family, rta_tb[IFA_ADDRESS]));
			log_trace("ifindex=%d peer_addr=%s", info->ifindex, info->peer_addr);
		}
	}

	if (rta_tb[IFA_BROADCAST] && info->ifa_family == AF_INET) {
		strcpy(info->brd_addr, format_host_rta(ifa->ifa_family, rta_tb[IFA_BROADCAST]));
		log_trace("ifindex=%d brd_addr=%s", info->ifindex, info->brd_addr);
	}

	/* TO REMOVE */
	rtnl_rtscope_n2a(ifa->ifa_scope, b1, sizeof(b1));
	return 0;
}

static int get_selected_addrinfo(struct ifinfomsg *ifi, struct nlmsg_list *ainfo, netif_info_t *info)
{
	info->ifa_family = AF_UNSPEC;

	for ( ; ainfo ;  ainfo = ainfo->next) {
		struct nlmsghdr *n = &ainfo->h;
		struct ifaddrmsg *ifa = NLMSG_DATA(n);

		if (n->nlmsg_type != RTM_NEWADDR)
			continue;

		if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
			return -1;

		if (ifa->ifa_index != ifi->ifi_index)
			continue;
		/* Retrieve only one IP address instead of all of them */
		if (info->ifa_family != AF_UNSPEC)
			continue;

		get_addrinfo(n, info);
	}

	return 0;
}

int get_linkinfo(struct nlmsghdr *n, netif_info_t *info)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX+1];
	int len = n->nlmsg_len;
	const char *name;
	SPRINT_BUF(b1);

	if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	if (ifindex && ifi->ifi_index != ifindex)
		return -1;

	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi), len, NLA_F_NESTED);

	name = get_ifname_rta(ifi->ifi_index, tb[IFLA_IFNAME]);
	if (!name)
		return -1;

	info->ifindex = ifi->ifi_index;
	strcpy(info->ifname, name);
	log_trace("ifindex=%d if=%s", ifi->ifi_index, info->ifname);

	if (tb[IFLA_OPERSTATE]) {
		info->state = get_operstate(rta_getattr_u8(tb[IFLA_OPERSTATE]));
	} else
		info->state = IF_STATE_UNKNOWN;	

	log_trace("ifindex=%d state=%d", ifi->ifi_index, info->state);
	strcpy(info->link_type, ll_type_n2a(ifi->ifi_type, b1, sizeof(b1)));
	log_trace("ifindex=%d link_type=%s", ifi->ifi_index, info->link_type);
	if (tb[IFLA_ADDRESS]) {
		if (RTA_PAYLOAD(tb[IFLA_ADDRESS]) == ETH_ALEN) {
			memcpy(info->mac_addr, RTA_DATA(tb[IFLA_ADDRESS]), ETH_ALEN);
			log_trace("ifindex=%d mac_address=%s", ifi->ifi_index, ll_addr_n2a(info->mac_addr, ETH_ALEN, ifi->ifi_type, b1, sizeof(b1)));
		}
	}

	return 1;
}

UT_array *get_interfaces(int if_id)
{
	struct nlmsg_chain linfo = { NULL, NULL};
	struct nlmsg_chain _ainfo = { NULL, NULL}, *ainfo = &_ainfo;
	struct nlmsg_list *l;

	UT_array *arr = NULL;
	utarray_new(arr, &netif_info_icd);

	if (rtnl_open(&rth, 0) < 0) {
		log_trace("rtnl_open error");
		goto err;
	}

	rtnl_set_strict_dump(&rth);

	if (ip_link_list(iplink_filter_req, &linfo) != 0) {
		log_trace("ip_link_list error");
		goto err;
	}

	if (ip_addr_list(ainfo, if_id) != 0) {
		log_trace("ip_addr_list error");
		goto err;
	}

	ipaddr_filter(&linfo, ainfo);

	for (l = linfo.head; l; l = l->next) {
		netif_info_t el;
		struct nlmsghdr *n = &l->h;
		struct ifinfomsg *ifi = NLMSG_DATA(n);
		int res = 0;

		res = get_linkinfo(n, &el);
		if (res >= 0)
			get_selected_addrinfo(ifi, ainfo->head, &el);
		
		utarray_push_back(arr, &el);
	}

	free_nlmsg_chain(ainfo);
	free_nlmsg_chain(&linfo);
	rtnl_close(&rth);
	return arr;

err:
	free_nlmsg_chain(ainfo);
	free_nlmsg_chain(&linfo);
	rtnl_close(&rth);
	utarray_free(arr);
	return NULL;
}

static int accept_msg(struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg)
{
	struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(n);

	if (n->nlmsg_type == NLMSG_ERROR &&
	    (err->error == -EOPNOTSUPP || err->error == -EINVAL))
		have_rtnl_newlink = 0;
	else
		have_rtnl_newlink = 1;
	return -1;
}

static int iplink_have_newlink(void)
{
	struct {
		struct nlmsghdr		n;
		struct ifinfomsg	i;
		char			buf[1024];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.n.nlmsg_type = RTM_NEWLINK,
		.i.ifi_family = AF_UNSPEC,
	};

	if (have_rtnl_newlink < 0) {
		if (rtnl_send(&rth, &req.n, req.n.nlmsg_len) < 0) {
			log_err_ex("request send failed");
		}
		rtnl_listen(&rth, accept_msg, NULL);
	}
	return have_rtnl_newlink;
}

static int nl_get_ll_addr_len(const char *ifname)
{
	int len;
	int dev_index = ll_name_to_index(ifname);
	struct iplink_req req = {
		.n = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST
		},
		.i = {
			.ifi_family = /*preferred_family*/0,
			.ifi_index = dev_index,
		}
	};
	struct nlmsghdr *answer;
	struct rtattr *tb[IFLA_MAX+1];

	if (dev_index == 0)
		return -1;

	if (rtnl_talk(&rth, &req.n, &answer) < 0)
		return -1;

	len = answer->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) {
		os_free(answer);
		return -1;
	}

	parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(NLMSG_DATA(answer)),
			   len, NLA_F_NESTED);
	if (!tb[IFLA_ADDRESS]) {
		os_free(answer);
		return -1;
	}

	len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
	os_free(answer);
	return len;
}

int iplink_parse(int argc, char **argv, struct iplink_req *req, char **type)
{
	char *name = NULL;
	char *dev = NULL;
	char *link = NULL;
	int ret, len;
	char abuf[32];
	int addr_len = 0;

	ret = argc;

	while (argc > 0) {
		if (strcmp(*argv, "up") == 0) {
			req->i.ifi_change |= IFF_UP;
			req->i.ifi_flags |= IFF_UP;
		} else if (strcmp(*argv, "down") == 0) {
			req->i.ifi_change |= IFF_UP;
			req->i.ifi_flags &= ~IFF_UP;
		} else if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			if (name)
				duparg("name", *argv);
			if (check_ifname(*argv))
				invarg("\"name\" not a valid ifname", *argv);
			name = *argv;
			if (!dev)
				dev = name;
		} else if (matches(*argv, "link") == 0) {
			NEXT_ARG();
			link = *argv;
		} else if (matches(*argv, "address") == 0) {
			NEXT_ARG();
			addr_len = ll_addr_a2n(abuf, sizeof(abuf), *argv);
			if (addr_len < 0)
				return -1;
			addattr_l(&req->n, sizeof(*req),
				  IFLA_ADDRESS, abuf, addr_len);
		} else if (matches(*argv, "broadcast") == 0 ||
			   strcmp(*argv, "brd") == 0) {
			NEXT_ARG();
			len = ll_addr_a2n(abuf, sizeof(abuf), *argv);
			if (len < 0)
				return -1;
			addattr_l(&req->n, sizeof(*req),
				  IFLA_BROADCAST, abuf, len);
		} else if (matches(*argv, "type") == 0) {
			NEXT_ARG();
			*type = *argv;
			argc--; argv++;
			break;
		} else {
			if (strcmp(*argv, "dev") == 0)
				NEXT_ARG();
			if (dev != name)
				duparg2("dev", *argv);
			if (check_altifname(*argv))
				invarg("\"dev\" not a valid ifname", *argv);
			dev = *argv;
		}
		argc--; argv++;
	}

	ret -= argc;

	/* Allow "ip link add dev" and "ip link add name" */
	if (!name)
		name = dev;
	else if (!dev)
		dev = name;
	else if (!strcmp(name, dev))
		name = dev;

	if (dev && addr_len && !(req->n.nlmsg_flags & NLM_F_CREATE)) {
		int halen = nl_get_ll_addr_len(dev);

		if (halen >= 0 && halen != addr_len) {
			log_trace("Invalid address length %d - must be %d bytes\n", addr_len, halen);
			return -1;
		}
	}

	// if (!(req->n.nlmsg_flags & NLM_F_CREATE)) {
	// 	if (!dev) {
	// 		fprintf(stderr,
	// 			"Not enough information: \"dev\" argument is required.\n");
	// 		exit(-1);
	// 	}

	// 	req->i.ifi_index = ll_name_to_index(dev);
	// 	if (!req->i.ifi_index)
	// 		return nodev(dev);

	// 	/* Not renaming to the same name */
	// 	if (name == dev)
	// 		name = NULL;
	// } else {
	// 	if (name != dev) {
	// 		fprintf(stderr,
	// 			"both \"name\" and \"dev\" cannot be used when creating devices.\n");
	// 		exit(-1);
	// 	}

	// 	if (link) {
	// 		int ifindex;

	// 		ifindex = ll_name_to_index(link);
	// 		if (!ifindex)
	// 			return nodev(link);
	// 		addattr32(&req->n, sizeof(*req), IFLA_LINK, ifindex);
	// 	}

	// 	req->i.ifi_index = index;
	// }

	if (name) {
		addattr_l(&req->n, sizeof(*req), IFLA_IFNAME, name, strlen(name) + 1);
	}

	return ret;
}

static int iplink_modify(int cmd, unsigned int flags, int argc, char **argv)
{
	char *type = NULL;
	struct iplink_req req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.i.ifi_family = /*preferred_family*/0,
	};

	int ret;
	ret = iplink_parse(argc, argv, &req, &type);
	if (ret < 0)
		return ret;

	if (type) {
		struct rtattr *linkinfo;

		linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, type, strlen(type));
		addattr_nest_end(&req.n, linkinfo);
	} else if (flags & NLM_F_CREATE) {
		fprintf(stderr,
			"Not enough information: \"type\" argument is required\n");
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -2;

	/* remove device from cache; next use can refresh with new data */
	ll_drop_by_index(req.i.ifi_index);
	return 0;
}

bool create_interface(char *if_name, char *type)
{
	int ret;
	char *argv[4] = {"name", if_name, "type", type};
	
	log_trace("create_interface for if_name=%s type=%s", if_name, type);

	if (rtnl_open(&rth, 0) < 0) {
		log_trace("rtnl_open error");
		goto err;
	}

	rtnl_set_strict_dump(&rth);
	
	if (iplink_have_newlink()) {
		ret = iplink_modify(RTM_NEWLINK, NLM_F_CREATE|NLM_F_EXCL, 4, argv);
		if (ret != 0) {
			log_trace("iplink_modify error %d", ret);
			goto err;
		}
	} else {
		log_trace("iplink_have_newlink error");
		goto err;
	}

	rtnl_close(&rth);
	return true;

err:
	rtnl_close(&rth);
	return false;
}

static int default_scope(inet_prefix *lcl)
{
	if (lcl->family == AF_INET) {
		if (lcl->bytelen >= 1 && *(__u8 *)&lcl->data == 127)
			return RT_SCOPE_HOST;
	}
	return 0;
}

static int ipaddr_modify(int cmd, int flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr	n;
		struct ifaddrmsg	ifa;
		char			buf[256];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | flags,
		.n.nlmsg_type = cmd,
		.ifa.ifa_family = /*preferred_family*/0,
	};
	char  *d = NULL;
	inet_prefix lcl = {};
	inet_prefix peer;
	int local_len = 0;
	int brd_len = 0;
	unsigned int ifa_flags = 0;

	while (argc > 0) {
		if (matches(*argv, "broadcast") == 0 ||
			   strcmp(*argv, "brd") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			if (brd_len)
				duparg("broadcast", *argv);

			get_addr(&addr, *argv, req.ifa.ifa_family);
			if (req.ifa.ifa_family == AF_UNSPEC)
				req.ifa.ifa_family = addr.family;
			addattr_l(&req.n, sizeof(req), IFA_BROADCAST, &addr.data, addr.bytelen);
			brd_len = addr.bytelen;
		} else if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			d = *argv;
		} else {
			if (local_len)
				duparg2("local", *argv);
			get_prefix(&lcl, *argv, req.ifa.ifa_family);
			if (req.ifa.ifa_family == AF_UNSPEC)
				req.ifa.ifa_family = lcl.family;
			addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);
			local_len = lcl.bytelen;
		}
		argc--; argv++;
	}

	if (ifa_flags <= 0xff)
		req.ifa.ifa_flags = ifa_flags;
	else
		addattr32(&req.n, sizeof(req), IFA_FLAGS, ifa_flags);

	if (d == NULL) {
		log_trace("Not enough information: \"dev\" argument is required.");
		return -1;
	}

	if (local_len) {
		if (cmd == RTM_DELADDR && lcl.family == AF_INET && !(lcl.flags & PREFIXLEN_SPECIFIED)) {
			log_trace(
			    "Warning: Executing wildcard deletion to stay compatible with old scripts.\n"
			    "         Explicitly specify the prefix length (%d) to avoid this warning.\n"
			    "         This special behaviour is likely to disappear in further releases,\n"
			    "         fix your scripts!", local_len*8);
		} else {
			peer = lcl;
			addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &lcl.data, lcl.bytelen);
		}
	}

	if (req.ifa.ifa_prefixlen == 0)
		req.ifa.ifa_prefixlen = lcl.bitlen;

	if (brd_len < 0 && cmd != RTM_DELADDR) {
		inet_prefix brd;
		int i;

		if (req.ifa.ifa_family != AF_INET) {
			log_trace("Broadcast can be set only for IPv4 addresses");
			return -1;
		}

		brd = peer;
		if (brd.bitlen <= 30) {
			for (i = 31; i >= brd.bitlen; i--) {
				if (brd_len == -1)
					brd.data[0] |= htonl(1<<(31-i));
				else
					brd.data[0] &= ~htonl(1<<(31-i));
			}
			addattr_l(&req.n, sizeof(req), IFA_BROADCAST, &brd.data, brd.bytelen);
			brd_len = brd.bytelen;
		}
	}

	if (cmd != RTM_DELADDR)
		req.ifa.ifa_scope = default_scope(&lcl);

	req.ifa.ifa_index = ll_name_to_index(d);
	if (!req.ifa.ifa_index)
		return nodev(d);

	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -2;

	return 0;
}

bool set_interface_ip(char *ip_addr, char *brd_addr, char *if_name)
{
	char *argv[5] = {ip_addr, "brd", brd_addr, "dev", if_name};

	log_trace("set_interface_ip for if_name=%s ip_addr=%s brd_addr=%s", if_name, ip_addr, brd_addr);

	if (rtnl_open(&rth, 0) < 0) {
		log_trace("rtnl_open error");
		goto err;
	}

	rtnl_set_strict_dump(&rth);
	
	int ret;
	ret = ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE|NLM_F_EXCL, 5, argv);
	if (ret != 0) {
		log_trace("ipaddr_modify error %d", ret);
		goto err;
	}

	rtnl_close(&rth);
	return true;

err:
	rtnl_close(&rth);
	return false;
}

bool set_interface_state(char *if_name, bool state)
{
	char *if_state = (state) ? "up" : "down";
	char *argv[3] = {"dev", if_name, if_state};
	
	log_trace("set_interface_state for if_name=%s if_state=%s", if_name, if_state);

	if (rtnl_open(&rth, 0) < 0) {
		log_trace("rtnl_open error");
		goto err;
	}

	rtnl_set_strict_dump(&rth);
	
	int ret;

	if (iplink_have_newlink()) {
		ret = iplink_modify(RTM_NEWLINK, 0, 3, argv);
		if (ret != 0) {
			log_trace("iplink_modify error %d", ret);
			goto err;
		}
	} else {
		log_trace("iplink_have_newlink error");
		goto err;
	}

	rtnl_close(&rth);
	return true;

err:
	rtnl_close(&rth);
	return false;
}

bool reset_interface(char *if_name)
{
  log_trace("Resseting interface state for if_name=%s", if_name);
  if (!set_interface_state(if_name, false)) {
    log_trace("set_interface_state fail");
    return false;
  }

  if (!set_interface_state(if_name, true)) {
    log_trace("set_interface_state fail");
    return false;
  }

  return true;
}

int get_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname)
{
  hmap_if_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  if(ifname == NULL) {
  	log_trace("ifname param is NULL");
  	return -1;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t), s); /* id already in the hash? */

  if (s != NULL) {
	memcpy(ifname, s->value, IFNAMSIZ);
    return 1;
  }
 
  return 0;
}

bool put_if_mapper(hmap_if_conn **hmap, in_addr_t subnet, char *ifname)
{
  hmap_if_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return false;
  }

  if (ifname == NULL) {
	log_trace("ifname param is NULL");
	return false;
  }

  HASH_FIND(hh, *hmap, &subnet, sizeof(in_addr_t), s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_if_conn *) os_malloc(sizeof(hmap_if_conn));
	if (s == NULL) {
	  log_err("os_malloc");
	  return false;
	}

	// Copy the key and value
	s->key = subnet;
    memcpy(s->value, ifname, IFNAMSIZ);

    HASH_ADD(hh, *hmap, key, sizeof(in_addr_t), s);
  } else {
	// Copy the value
    memcpy(s->value, ifname, IFNAMSIZ);
  }

  return true;	
}

void free_if_mapper(hmap_if_conn **hmap)
{
  hmap_if_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
    os_free(current);            						/* free it */
  }
}

int get_vlan_mapper(hmap_vlan_conn **hmap, int vlanid, char *ifname)
{
  hmap_vlan_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return -1;
  }

  if(ifname == NULL) {
	log_trace("ifname param is NULL");
	return -1;
  }

  HASH_FIND(hh, *hmap, &vlanid, sizeof(int), s); /* id already in the hash? */

  if (s != NULL) {
	memcpy(ifname, s->value, IFNAMSIZ);
	return 1;
  }
 
  return 0;
}

bool put_vlan_mapper(hmap_vlan_conn **hmap, int vlanid, char *ifname)
{
  hmap_vlan_conn *s;

  if (hmap == NULL) {
	log_trace("hmap param is NULL");
	return false;
  }

  if (ifname == NULL) {
	log_trace("ifname param is NULL");
	return false;
  }

  HASH_FIND(hh, *hmap, &vlanid, sizeof(int), s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_vlan_conn *) os_malloc(sizeof(hmap_vlan_conn));
	if (s == NULL) {
	  log_err("os_malloc");
	  return false;
	}

	// Copy the key and value
	s->key = vlanid;
    memcpy(s->value, ifname, IFNAMSIZ);

    HASH_ADD(hh, *hmap, key, sizeof(int), s);
  } else {
	// Copy the value
    memcpy(s->value, ifname, IFNAMSIZ);
  }

  return true;	
}

void free_vlan_mapper(hmap_vlan_conn **hmap)
{
  hmap_vlan_conn *current, *tmp;

  HASH_ITER(hh, *hmap, current, tmp) {
  	HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
  	os_free(current);            						/* free it */
  }
}

bool ip_2_nbo(char *ip, char *subnet_mask, in_addr_t *addr)
{
	in_addr_t subnet;

	if (addr == NULL) {
		log_trace("addr param is NULL");
		return false;
	}

  if ((subnet = inet_network(subnet_mask)) == -1) {
		log_trace("Invalid subnet mask address");
		return -1;
	}

	if ((*addr = inet_network(ip)) == -1) {
		log_trace("Invalid ip address");
		return false;
	}

	*addr = *addr & subnet;

	return true;
}

char *in_addr_2_ip(struct in_addr *addr, char *ip)
{
  return inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
}

const char *bit32_2_ip(uint32_t addr, char *ip)
{
  struct in_addr in;
  in.s_addr = addr;
  return inet_ntop(AF_INET, &in, ip, INET_ADDRSTRLEN);
}

int find_subnet_address(UT_array *config_ifinfo_array, char *ip, in_addr_t *subnet_addr)
{
  config_ifinfo_t *p = NULL;
  in_addr_t addr_config;

  if (config_ifinfo_array == NULL) {
    log_trace("config_ifinfo_array param is NULL");
    return false;
  }

  if (ip == NULL) {
	log_trace("ip param is NULL");
	return -1;
  }

  if (subnet_addr == NULL) {
	log_trace("subnet_addr param is NULL");
	return -1;
  }

  while(p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) {
	if (!ip_2_nbo(p->ip_addr, p->subnet_mask, &addr_config)) {
	  log_trace("ip_2_nbo fail");
	  return -1;
	}

	if (!ip_2_nbo(ip, p->subnet_mask, subnet_addr)) {
	  log_trace("ip_2_nbo fail");
	  return -1;
	}

	if (addr_config == *subnet_addr) {
	  return 0;
	}
  }

  return 1;
}

bool get_ifname_from_ip(hmap_if_conn **if_mapper, UT_array *config_ifinfo_array, char *ip, char *ifname)
{
  in_addr_t subnet_addr;

  if (find_subnet_address(config_ifinfo_array, ip, &subnet_addr) != 0) {
    log_trace("find_subnet_address fail");
    return false;
  }

  int ret = get_if_mapper(if_mapper, subnet_addr, ifname);
  if (ret < 0) {
    log_trace("get_if_mapper fail");
    return false;
  } else if (ret == 0) {
	log_trace("subnet not in mapper");
	return false;
  }

  return true;
}

bool validate_ipv4_string(char *ip)
{
  struct sockaddr_in sa;
  char proc_ip[IP_LEN];
  char *netmask_sep = strchr(ip, '/');
  int netmask_char_size;

  memset(proc_ip, '\0', IP_LEN);
  if (netmask_sep) {
	strncpy(proc_ip, ip, strlen(ip) - strlen(netmask_sep));
	netmask_char_size = strlen(netmask_sep + 1);
	if (netmask_char_size > 2 || netmask_char_size < 1) {
	  log_trace("Invalid netmask");
	  return false;
	}
	if (!is_number(netmask_sep + 1)) {
	  log_trace("Invalid netmask");
	  return false;
	}
	if (strtol(netmask_sep + 1, (char **)NULL, 10) > 32) {
	  log_trace("Invalid netmask");
	  return false;
	}
  } else
    strcpy(proc_ip, ip);

  int ret = inet_pton(AF_INET, proc_ip, &(sa.sin_addr));
  if (ret == -1) {
	log_err("inet_pton");
	return false;
  }
  return ret > 0;
}