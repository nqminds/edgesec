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
 * @file iface.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the network interface utilities.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <fnmatch.h>
#include <arpa/inet.h>

#include "allocs.h"
#include "os.h"
#include "log.h"
#include "iface.h"
#include "ifaceu.h"
#include "net.h"

#ifdef WITH_NETLINK_SERVICE
#include "nl.h"
#endif

#include "utarray.h"

UT_array *get_interfaces(int id)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_get_interfaces(id);
#else
  (void) id;

	log_trace("get_interfaces not implemented");
	return NULL;
#endif
}


bool create_interface(char *ifname, char *type)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_create_interface(ifname, type);
#else
  (void) ifname;
  (void) type;

	log_trace("create_interface not implemented");
	return NULL;
#endif
}


bool set_interface_ip(char *ip_addr, char *brd_addr, char *ifname)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_set_interface_ip(ip_addr, brd_addr, ifname);
#else
  (void) ip_addr;
  (void) brd_addr;
  (void) ifname;

	log_trace("set_interface_ip not implemented");
	return NULL;
#endif
}

bool set_interface_state(char *ifname, bool state)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_set_interface_state(ifname, state);
#else
  (void) ifname;
  (void) state;

	log_trace("set_interface_state not implemented");
	return NULL;
#endif
}

bool reset_interface(char *ifname)
{
  log_trace("Resseting interface state for if_name=%s", ifname);
  if (!set_interface_state(ifname, false)) {
    log_trace("set_interface_state fail");
    return false;
  }

  if (!set_interface_state(ifname, true)) {
    log_trace("set_interface_state fail");
    return false;
  }

  return true;
}

int is_interface_vlan(const char *ifname)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_is_iw_vlan(ifname);
#else
  (void) ifname;

	log_trace("is_interface_vlan not implemented");
	return -1;
#endif
}

char* get_vlan_interface(char *buf)
{
#ifdef WITH_NETLINK_SERVICE
	return nl_get_valid_iw(buf);
#else
  (void) buf;

	log_trace("get_vlan_interface not implemented");
	return NULL;
#endif
}
