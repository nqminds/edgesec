/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the netlink utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <fnmatch.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <arpa/inet.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "libnetlink.h"
#include "ll_map.h"
#include "utils.h"
#include "rt_names.h"

#include "linux/if_addr.h"
#include "linux/if_infiniband.h"

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "nl.h"
#include "net.h"
#include "iface_mapper.h"
#include "ifaceu.h"

static int ifindex = 0;
struct rtnl_handle rth = {.fd = -1};
static int have_rtnl_newlink = -1;

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};
static const UT_icd netiw_info_icd = {sizeof(netiw_info_t), NULL, NULL, NULL};

static const char *ifmodes[NL80211_IFTYPE_MAX + 1] = {
    "unspecified", "IBSS",   "managed",    "AP",
    "AP/VLAN",     "WDS",    "monitor",    "mesh point",
    "P2P-client",  "P2P-GO", "P2P-device", "outside context of a BSS",
    "NAN",
};

static int store_nlmsg(struct nlmsghdr *n, void *arg) {
  struct nlmsg_chain *lchain = (struct nlmsg_chain *)arg;
  struct nlmsg_list *h;

  h = os_malloc(n->nlmsg_len + sizeof(void *));
  if (h == NULL)
    return -1;

  os_memcpy(&h->h, n, n->nlmsg_len);
  h->next = NULL;

  if (lchain->tail)
    lchain->tail->next = h;
  else
    lchain->head = h;
  lchain->tail = h;

  ll_remember_index(n, NULL);
  return 0;
}

void free_nlmsg_chain(struct nlmsg_chain *info) {
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
int ip_link_list(req_filter_fn_t filter_fn, struct nlmsg_chain *linfo) {
  if (rtnl_linkdump_req_filter_fn(&rth, 0, filter_fn) < 0) {
    log_errno("Cannot send dump request");
    return 1;
  }

  if (rtnl_dump_filter(&rth, store_nlmsg, linfo) < 0) {
    log_error("Dump terminated");
    return 1;
  }

  return 0;
}

static int iplink_filter_req(struct nlmsghdr *nlh, int reqlen) {
  int err;

  err = addattr32(nlh, reqlen, IFLA_EXT_MASK, RTEXT_FILTER_VF);
  if (err)
    return err;

  return 0;
}

static int ipaddr_dump_filter(struct nlmsghdr *nlh, int reqlen) {
  (void)reqlen;

  struct ifaddrmsg *ifa = NLMSG_DATA(nlh);

  ifa->ifa_index = ifindex;

  return 0;
}

static int ip_addr_list(struct nlmsg_chain *ainfo, int if_id) {
  ifindex = if_id;

  if (rtnl_addrdump_req(&rth, 0, ipaddr_dump_filter) < 0) {
    log_errno("Cannot send dump request");
    return 1;
  }

  if (rtnl_dump_filter(&rth, store_nlmsg, ainfo) < 0) {
    log_error("Dump terminated");
    return 1;
  }

  return 0;
}

static void ipaddr_filter(struct nlmsg_chain *linfo,
                          struct nlmsg_chain *ainfo) {
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

      if (ifa->ifa_index != (uint32_t)ifi->ifi_index)
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

enum IF_STATE get_operstate(__u8 state) {
  if (state >= 7) {
    return IF_STATE_OTHER;
  } else {
    return (enum IF_STATE)state;
  }
}

int get_addrinfo(struct nlmsghdr *n, netif_info_t *info) {
  struct ifaddrmsg *ifa = NLMSG_DATA(n);
  int len = n->nlmsg_len;
  struct rtattr *rta_tb[IFA_MAX + 1];

  SPRINT_BUF(b1);

  if (n->nlmsg_type != RTM_NEWADDR && n->nlmsg_type != RTM_DELADDR)
    return 0;
  len -= NLMSG_LENGTH(sizeof(*ifa));
  if (len < 0) {
    log_error("BUG: wrong nlmsg len %d\n", len);
    return -1;
  }

  parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
               n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

  if (!rta_tb[IFA_LOCAL])
    rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
  if (!rta_tb[IFA_ADDRESS])
    rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

  if (ifindex && (uint32_t)ifindex != ifa->ifa_index)
    return 0;

  info->ifa_family = ifa->ifa_family;
  const char *name = family_name(ifa->ifa_family);

  if (*name != '?') {
    log_trace("ifindex=%d family=%s", info->ifindex, name);
  } else {
    log_trace("ifindex=%d family_index=%d", info->ifindex, info->ifa_family);
  }

  if (rta_tb[IFA_LOCAL] && info->ifa_family == AF_INET) {
    os_strlcpy(info->ip_addr,
               format_host_rta(ifa->ifa_family, rta_tb[IFA_LOCAL]),
               OS_INET_ADDRSTRLEN);
    log_trace("ifindex=%d ip_addr=%s", info->ifindex, info->ip_addr);
    if (rta_tb[IFA_ADDRESS] &&
        memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]), RTA_DATA(rta_tb[IFA_LOCAL]), 4)) {
      os_strlcpy(info->peer_addr,
                 format_host_rta(ifa->ifa_family, rta_tb[IFA_ADDRESS]),
                 OS_INET_ADDRSTRLEN);
      log_trace("ifindex=%d peer_addr=%s", info->ifindex, info->peer_addr);
    }
  }

  if (rta_tb[IFA_BROADCAST] && info->ifa_family == AF_INET) {
    os_strlcpy(info->brd_addr,
               format_host_rta(ifa->ifa_family, rta_tb[IFA_BROADCAST]),
               OS_INET_ADDRSTRLEN);
    log_trace("ifindex=%d brd_addr=%s", info->ifindex, info->brd_addr);
  }

  /* TO REMOVE */
  rtnl_rtscope_n2a(ifa->ifa_scope, b1, sizeof(b1));
  return 0;
}

static int get_selected_addrinfo(struct ifinfomsg *ifi,
                                 struct nlmsg_list *ainfo, netif_info_t *info) {
  info->ifa_family = AF_UNSPEC;

  for (; ainfo; ainfo = ainfo->next) {
    struct nlmsghdr *n = &ainfo->h;
    struct ifaddrmsg *ifa = NLMSG_DATA(n);

    if (n->nlmsg_type != RTM_NEWADDR)
      continue;

    if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
      return -1;

    if (ifa->ifa_index != (uint32_t)ifi->ifi_index)
      continue;
    /* Retrieve only one IP address instead of all of them */
    if (info->ifa_family != AF_UNSPEC)
      continue;

    get_addrinfo(n, info);
  }

  return 0;
}

int get_linkinfo(struct nlmsghdr *n, netif_info_t *info) {
  struct ifinfomsg *ifi = NLMSG_DATA(n);
  struct rtattr *tb[IFLA_MAX + 1];
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
  os_strlcpy(info->ifname, name, IFNAMSIZ);
  log_trace("ifindex=%d if=%s", ifi->ifi_index, info->ifname);

  if (tb[IFLA_OPERSTATE]) {
    info->state = get_operstate(rta_getattr_u8(tb[IFLA_OPERSTATE]));
  } else
    info->state = IF_STATE_UNKNOWN;

  log_trace("ifindex=%d state=%d", ifi->ifi_index, info->state);
  os_strlcpy(info->link_type, ll_type_n2a(ifi->ifi_type, b1, sizeof(b1)),
             LINK_TYPE_LEN);
  log_trace("ifindex=%d link_type=%s", ifi->ifi_index, info->link_type);
  if (tb[IFLA_ADDRESS]) {
    if (RTA_PAYLOAD(tb[IFLA_ADDRESS]) == ETHER_ADDR_LEN) {
      os_memcpy(info->mac_addr, RTA_DATA(tb[IFLA_ADDRESS]), ETHER_ADDR_LEN);
      log_trace("ifindex=%d mac_address=%s", ifi->ifi_index,
                ll_addr_n2a(info->mac_addr, ETHER_ADDR_LEN, ifi->ifi_type, b1,
                            sizeof(b1)));
    }
  }

  return 1;
}

static int accept_msg(struct rtnl_ctrl_data *ctrl, struct nlmsghdr *n,
                      void *arg) {
  (void)ctrl;
  (void)arg;

  struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(n);

  if (n->nlmsg_type == NLMSG_ERROR &&
      (err->error == -EOPNOTSUPP || err->error == -EINVAL))
    have_rtnl_newlink = 0;
  else
    have_rtnl_newlink = 1;
  return -1;
}

static int iplink_have_newlink(void) {
  struct {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[1024];
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

static int nl_get_ll_addr_len(const char *ifname) {
  int len;
  int dev_index = ll_name_to_index(ifname);
  struct iplink_req req = {
      .n = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .nlmsg_type = RTM_GETLINK,
            .nlmsg_flags = NLM_F_REQUEST},
      .i = {
          .ifi_family = /*preferred_family*/ 0,
          .ifi_index = dev_index,
      }};
  struct nlmsghdr *answer;
  struct rtattr *tb[IFLA_MAX + 1];

  if (dev_index == 0)
    return -1;

  if (rtnl_talk(&rth, &req.n, &answer) < 0)
    return -1;

  len = answer->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
  if (len < 0) {
    os_free(answer);
    return -1;
  }

  parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(NLMSG_DATA(answer)), len,
                     NLA_F_NESTED);
  if (!tb[IFLA_ADDRESS]) {
    os_free(answer);
    return -1;
  }

  len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
  os_free(answer);
  return len;
}

int iplink_parse(int argc, const char *const *argv, struct iplink_req *req,
                 const char **type) {
  const char *name = NULL;
  const char *dev = NULL;
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
    } else if (matches(*argv, "address") == 0) {
      NEXT_ARG();
      addr_len = ll_addr_a2n(abuf, sizeof(abuf), *argv);
      if (addr_len < 0)
        return -1;
      addattr_l(&req->n, sizeof(*req), IFLA_ADDRESS, abuf, addr_len);
    } else if (matches(*argv, "broadcast") == 0 || strcmp(*argv, "brd") == 0) {
      NEXT_ARG();
      len = ll_addr_a2n(abuf, sizeof(abuf), *argv);
      if (len < 0)
        return -1;
      addattr_l(&req->n, sizeof(*req), IFLA_BROADCAST, abuf, len);
    } else if (matches(*argv, "type") == 0) {
      NEXT_ARG();
      *type = *argv;
      argc--;
      argv++;
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
    argc--;
    argv++;
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
      log_trace("Invalid address length %d - must be %d bytes\n", addr_len,
                halen);
      return -1;
    }
  }

  // if (!(req->n.nlmsg_flags & NLM_F_CREATE)) {
  // 	if (!dev) {
  // 		fprintf(stderr,
  // 			"Not enough information: \"dev\" argument is
  // required.\n"); 		exit(-1);
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
  // 			"both \"name\" and \"dev\" cannot be used when creating
  // devices.\n"); 		exit(-1);
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

static int iplink_modify(int cmd, unsigned int flags, int argc,
                         const char *const *argv) {
  const char *type = NULL;
  struct iplink_req req = {
      .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .n.nlmsg_flags = NLM_F_REQUEST | flags,
      .n.nlmsg_type = cmd,
      .i.ifi_family = /*preferred_family*/ 0,
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
    fprintf(stderr, "Not enough information: \"type\" argument is required\n");
    return -1;
  }

  if (rtnl_talk(&rth, &req.n, NULL) < 0)
    return -2;

  /* remove device from cache; next use can refresh with new data */
  ll_drop_by_index(req.i.ifi_index);
  return 0;
}

static int default_scope(inet_prefix *lcl) {
  if (lcl->family == AF_INET) {
    if (lcl->bytelen >= 1 && *(__u8 *)&lcl->data == 127)
      return RT_SCOPE_HOST;
  }
  return 0;
}

static int ipaddr_modify(int cmd, int flags, int argc,
                         const char *const *argv) {
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg ifa;
    char buf[256];
  } req = {
      .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
      .n.nlmsg_flags = NLM_F_REQUEST | flags,
      .n.nlmsg_type = cmd,
      .ifa.ifa_family = /*preferred_family*/ 0,
  };
  const char *d = NULL;
  inet_prefix lcl;
  inet_prefix peer;
  int local_len = 0;
  int brd_len = 0;
  unsigned int ifa_flags = 0;

  os_memset(&lcl, 0, sizeof(inet_prefix));
  while (argc > 0) {
    if (matches(*argv, "broadcast") == 0 || strcmp(*argv, "brd") == 0) {
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
      // Get prefix temporarily modifies argv,
      // which may cause problems for multi-threading
      char argv_buf[256];
      argv_buf[255] = '\0'; // NUL terminate in case strncpy maxes out
      strncpy(argv_buf, *argv, sizeof(argv_buf) - 1);
      get_prefix(&lcl, argv_buf, req.ifa.ifa_family);
      if (req.ifa.ifa_family == AF_UNSPEC)
        req.ifa.ifa_family = lcl.family;
      addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);
      local_len = lcl.bytelen;
    }
    argc--;
    argv++;
  }

  if (ifa_flags <= 0xff)
    req.ifa.ifa_flags = ifa_flags;
  else
    addattr32(&req.n, sizeof(req), IFA_FLAGS, ifa_flags);

  if (d == NULL) {
    log_error("Not enough information: \"dev\" argument is required.");
    return -1;
  }

  if (local_len) {
    if (cmd == RTM_DELADDR && lcl.family == AF_INET &&
        !(lcl.flags & PREFIXLEN_SPECIFIED)) {
      log_warn("Warning: Executing wildcard deletion to stay compatible with "
               "old scripts.\n"
               "         Explicitly specify the prefix length (%d) to avoid "
               "this warning.\n"
               "         This special behaviour is likely to disappear in "
               "further releases,\n"
               "         fix your scripts!",
               local_len * 8);
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
      log_error("Broadcast can be set only for IPv4 addresses");
      return -1;
    }

    brd = peer;
    if (brd.bitlen <= 30) {
      for (i = 31; i >= brd.bitlen; i--) {
        if (brd_len == -1)
          brd.data[0] |= htonl(1 << (31 - i));
        else
          brd.data[0] &= ~htonl(1 << (31 - i));
      }
      addattr_l(&req.n, sizeof(req), IFA_BROADCAST, &brd.data, brd.bytelen);
      brd_len = brd.bytelen;
    }
  }

  if (cmd != RTM_DELADDR)
    req.ifa.ifa_scope = default_scope(&lcl);

  req.ifa.ifa_index = ll_name_to_index(d);
  if (!req.ifa.ifa_index) {

    log_error("ipaddr_modify error: could not find interface '%s'", d);
    return -1;
  }

  if (rtnl_talk(&rth, &req.n, NULL) < 0)
    return -2;

  return 0;
}

UT_array *nl_get_interfaces(int if_id) {
  struct nlmsg_chain linfo = {NULL, NULL};
  struct nlmsg_chain _ainfo = {NULL, NULL}, *ainfo = &_ainfo;
  struct nlmsg_list *l;

  UT_array *arr = NULL;
  utarray_new(arr, &netif_info_icd);

  if (rtnl_open(&rth, 0) < 0) {
    log_error("rtnl_open error");
    goto nl_get_interfaces_err;
  }

  rtnl_set_strict_dump(&rth);

  if (ip_link_list(iplink_filter_req, &linfo) != 0) {
    log_error("ip_link_list error");
    goto nl_get_interfaces_err;
  }

  if (ip_addr_list(ainfo, if_id) != 0) {
    log_error("ip_addr_list error");
    goto nl_get_interfaces_err;
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

nl_get_interfaces_err:
  free_nlmsg_chain(ainfo);
  free_nlmsg_chain(&linfo);
  rtnl_close(&rth);
  utarray_free(arr);
  return NULL;
}

int nl_new_interface(const char *if_name, const char *type) {
  int ret;
  const char *argv[4] = {"name", if_name, "type", type};

  log_debug("nl_new_interface for if_name=%s type=%s", if_name, type);

  if (rtnl_open(&rth, 0) < 0) {
    log_error("rtnl_open error");
    goto nl_new_interface_err;
  }

  rtnl_set_strict_dump(&rth);

  if (iplink_have_newlink()) {
    ret = iplink_modify(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 4, argv);
    if (ret != 0) {
      log_error("iplink_modify error %d", ret);
      goto nl_new_interface_err;
    }
  } else {
    log_error("iplink_have_newlink error");
    goto nl_new_interface_err;
  }

  rtnl_close(&rth);
  return 0;

nl_new_interface_err:
  rtnl_close(&rth);
  return -1;
}

int nl_set_interface_ip(const struct nlctx *context, const char *ifname,
                        const char *ip_addr, const char *brd_addr,
                        const char *subnet_mask) {
  (void)context;

  char longip[OS_INET_ADDRSTRLEN];

  snprintf(longip, OS_INET_ADDRSTRLEN, "%s/%d", ip_addr,
           (int)get_short_subnet(subnet_mask));

  const char *argv[5] = {longip, "brd", brd_addr, "dev", ifname};

  log_debug("set_interface_ip for ifname=%s ip_addr=%s brd_addr=%s", ifname,
            longip, brd_addr);

  if (rtnl_open(&rth, 0) < 0) {
    log_error("rtnl_open error");
    goto nl_set_interface_ip_err;
  }

  rtnl_set_strict_dump(&rth);

  int ret;
  ret = ipaddr_modify(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, 5, argv);
  if (ret != 0) {
    log_error("nl_set_interface_ip error: ipaddr_modify failed with %d", ret);
    goto nl_set_interface_ip_err;
  }

  rtnl_close(&rth);
  return 0;

nl_set_interface_ip_err:
  rtnl_close(&rth);
  return -1;
}

int nl_set_interface_state(const char *if_name, bool state) {
  const char *if_state = (state) ? "up" : "down";
  const char *argv[3] = {"dev", if_name, if_state};

  log_debug("set_interface_state for if_name=%s if_state=%s", if_name,
            if_state);

  if (rtnl_open(&rth, 0) < 0) {
    log_error("rtnl_open error");
    goto nl_set_interface_state_err;
  }

  rtnl_set_strict_dump(&rth);

  int ret;

  if (iplink_have_newlink()) {
    ret = iplink_modify(RTM_NEWLINK, 0, 3, argv);
    if (ret != 0) {
      log_error("iplink_modify error %d", ret);
      goto nl_set_interface_state_err;
    }
  } else {
    log_error("iplink_have_newlink error");
    goto nl_set_interface_state_err;
  }

  rtnl_close(&rth);
  return 0;

nl_set_interface_state_err:
  rtnl_close(&rth);
  return -1;
}

struct nlctx *nl_init_context(void) {
  struct nlctx *context = os_zalloc(sizeof(struct nlctx));

  if (context == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  return context;
}

void nl_free_context(struct nlctx *context) {
  if (context != NULL) {
    os_free(context);
  }
}

int nl_create_interface(const struct nlctx *context, const char *ifname,
                        const char *type, const char *ip_addr,
                        const char *brd_addr, const char *subnet_mask) {
  if (ifname == NULL) {
    log_error("ifname param is NULL");
    return -1;
  }

  if (type == NULL) {
    log_error("type param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_error("ip_addr param is NULL");
    return -1;
  }

  if (brd_addr == NULL) {
    log_error("brd_addr param is NULL");
    return -1;
  }

  if (subnet_mask == NULL) {
    log_error("subnet_mask param is NULL");
    return -1;
  }

  if (nl_new_interface(ifname, type) < 0) {
    log_error("nl_new_interface fail");
    return -1;
  }

  if (nl_set_interface_ip(context, ifname, ip_addr, brd_addr, subnet_mask) <
      0) {
    log_error("nl_set_interface_ip fail");
    return -1;
  }

  if (nl_set_interface_state(ifname, true) < 0) {
    log_error("nl_set_interface_state fail");
    return -1;
  }

  return 0;
}

int nl_reset_interface(const char *ifname) {
  if (nl_set_interface_state(ifname, false) < 0) {
    log_error("nl_set_interface_state fail");
    return -1;
  }

  if (nl_set_interface_state(ifname, true) < 0) {
    log_error("nl_set_interface_state fail");
    return -1;
  }

  return 0;
}

static void mac_addr_n2a(char *mac_addr, const unsigned char *arg) {
  int i, l;

  l = 0;
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    if (i == 0) {
      sprintf(mac_addr + l, "%02x", arg[i]);
      l += 2;
    } else {
      sprintf(mac_addr + l, ":%02x", arg[i]);
      l += 3;
    }
  }
}

static const char *iftype_name(enum nl80211_iftype iftype, char *modebuf) {
  if (iftype <= NL80211_IFTYPE_MAX && ifmodes[iftype])
    return ifmodes[iftype];
  sprintf(modebuf, "Unknown mode (%d)", iftype);
  return modebuf;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
                         void *arg) {
  (void)nla;
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
    len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]),
                  nla_len(tb[NLMSGERR_ATTR_MSG]));
    log_trace("kernel reports: %*s\n", len,
              (char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
  }

  return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  (void)msg;
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  (void)msg;
  int *ret = arg;
  *ret = 0;
  return NL_STOP;
}

static int nl80211_init(struct nl80211_state *state) {
  int err;

  state->nl_sock = nl_socket_alloc();
  if (!state->nl_sock) {
    log_errno("Failed to allocate netlink socket");
    return -ENOMEM;
  }

  if (genl_connect(state->nl_sock)) {
    log_errno("Failed to connect to generic netlink");
    err = -ENOLINK;
    goto out_handle_destroy;
  }

  nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

  /* try to set NETLINK_EXT_ACK to 1, ignoring errors */
  err = 1;
  setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK,
             &err, sizeof(err));

  state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
  if (state->nl80211_id < 0) {
    log_errno("nl80211 not found");
    err = -ENOENT;
    goto out_handle_destroy;
  }

  return 0;

out_handle_destroy:
  nl_socket_free(state->nl_sock);
  return err;
}

static int process_phy_handler(struct nl_msg *msg, void *arg) {
  bool *isvalid = (bool *)arg;

  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  char *wiphy = NULL;
  if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
    wiphy = nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]);
    log_trace("Using Wiphy %s", wiphy);
  }

  if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
    char modebuf[100];
    struct nlattr *nl_mode;
    int rem_mode;
    nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES],
                        rem_mode) {
      const char *capability = (char *)iftype_name(nla_type(nl_mode), modebuf);
      log_trace("%s -> %s", wiphy, capability);
      if (!strcmp(capability, "AP/VLAN")) {
        *isvalid = true;
      }
    }
  }

  return NL_SKIP;
}

static int process_iface_handler(struct nl_msg *msg, void *arg) {
  UT_array *arr = (UT_array *)arg;
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  netiw_info_t element;

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

  if (tb_msg[NL80211_ATTR_IFNAME]) {
    os_strlcpy(element.ifname, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]),
               IFNAMSIZ);

    if (tb_msg[NL80211_ATTR_IFINDEX]) {
      element.ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
      log_trace("%s -> ifindex=%d", element.ifname, element.ifindex);
    }

    if (tb_msg[NL80211_ATTR_WDEV]) {
      element.wdev = nla_get_u64(tb_msg[NL80211_ATTR_WDEV]);
      log_trace("%s -> wdev=0x%llx", element.ifname,
                (unsigned long long)element.wdev);
    }

    if (tb_msg[NL80211_ATTR_MAC]) {
      char mac_addr[20];
      os_memcpy(element.addr, nla_data(tb_msg[NL80211_ATTR_MAC]),
                ETHER_ADDR_LEN);
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

static int8_t nl_new(struct nl80211_state *nlstate, struct nl_cb **cb,
                     struct nl_msg **msg, int *err) {
  if (nl80211_init(nlstate)) {
    return -1;
  }

  *msg = nlmsg_alloc();
  if (*msg == NULL) {
    log_error("failed to allocate netlink message");
    nl_socket_free(nlstate->nl_sock);
    return 1;
  }

  *cb = nl_cb_alloc(NL_CB_TYPE);
  if (*cb == NULL) {
    log_error("failed to allocate netlink callbacks\n");
    nlmsg_free(*msg);
    nl_socket_free(nlstate->nl_sock);
    return 1;
  }

  nl_cb_err(*cb, NL_CB_CUSTOM, error_handler, err);
  nl_cb_set(*cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, err);
  nl_cb_set(*cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, err);

  return 0;
}

int iwace_isvlan(uint32_t wiphy) {
  bool isvlan = false;
  int err = 1;
  struct nl_cb *cb;
  struct nl_msg *msg;
  struct nl80211_state nlstate;

  if (nl_new(&nlstate, &cb, &msg, &err) != 0) {
    log_error("nl_new fail");
    return -1;
  }

  genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
  NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, wiphy);

  if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0) {
    log_error("nl_send_auto_complete fail");
    nl_cb_put(cb);
    nlmsg_free(msg);
    nl_socket_free(nlstate.nl_sock);
    return -1;
  }

  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, process_phy_handler, &isvlan);

  while (err > 0) {
    nl_recvmsgs(nlstate.nl_sock, cb);
  }

  nl_cb_put(cb);
  nlmsg_free(msg);
  nl_socket_free(nlstate.nl_sock);
  return (isvlan) ? 1 : 0;

nla_put_failure:
  log_error("NLA_PUT_U32 failed");
  nl_cb_put(cb);
  nlmsg_free(msg);
  nl_socket_free(nlstate.nl_sock);
  return -1;
}

UT_array *get_netiw_info(void) {
  int err = 1;
  struct nl80211_state nlstate;
  struct nl_cb *cb;
  struct nl_msg *msg;
  UT_array *arr = NULL;
  utarray_new(arr, &netiw_info_icd);

  if (nl_new(&nlstate, &cb, &msg, &err) != 0)
    return NULL;

  genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, NLM_F_DUMP,
              NL80211_CMD_GET_INTERFACE, 0);

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

  log_error("NLA_PUT_U32 failed");
  nl_cb_put(cb);
  nlmsg_free(msg);
  nl_socket_free(nlstate.nl_sock);
  utarray_free(arr);
  return NULL;
}

int nl_is_iw_vlan(const char *ifname) {
  log_debug("Checking %s exists", ifname);
  if (!iface_exists(ifname)) {
    log_error("WiFi interface %s doesn't exist", ifname);
    return 1;
  }

  UT_array *netif_list = get_netiw_info();

  if (netif_list == NULL) {
    log_error("Couldn't list wifi interfaces");
    return -1;
  }

  netiw_info_t *el;
  for (el = (netiw_info_t *)utarray_front(netif_list); el != NULL;
       el = (netiw_info_t *)utarray_next(netif_list, el)) {
    if (!strcmp(el->ifname, ifname)) {
      int ret = iwace_isvlan(el->wiphy);
      if (ret == 0) {
        log_warn("WiFi interface %s doesn't suport vlan tagging", ifname);
        utarray_free(netif_list);
        return 1;
      } else if (ret == 1) {
        utarray_free(netif_list);
        return 0;
      } else {
        log_error("iwace_isvlan fail");
        utarray_free(netif_list);
        return -1;
      }
    }
  }

  utarray_free(netif_list);
  return -1;
}

char *nl_get_valid_iw(char buf[static IFNAMSIZ]) {
  UT_array *netif_list = get_netiw_info();

  if (netif_list == NULL) {
    log_error("Couldn't list wifi interfaces");
    return NULL;
  }

  if (buf == NULL) {
    log_error("if_buf param is NULL");
    utarray_free(netif_list);
    return NULL;
  }

  netiw_info_t *el;
  for (el = (netiw_info_t *)utarray_front(netif_list); el != NULL;
       el = (netiw_info_t *)utarray_next(netif_list, el)) {
    int ret = iwace_isvlan(el->wiphy);

    if (ret == 1) {
      os_strlcpy(buf, el->ifname, IFNAMSIZ);
      utarray_free(netif_list);
      return buf;
    } else if (ret < 0) {
      log_error("iwace_isvlan fail");
      utarray_free(netif_list);
      return NULL;
    }
  }

  utarray_free(netif_list);
  return NULL;
}
