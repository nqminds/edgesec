/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file net.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the network utilities.
 */

#include <linux/if.h>
#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>

#include "utarray.h"
#include "uthash.h"
#include "allocs.h"
#include "os.h"

bool validate_ipv4_string(char *ip)
{
  struct sockaddr_in sa;
  char proc_ip[IP_LEN];
  char *netmask_sep = strchr(ip, '/');
  int netmask_char_size, ret;
  size_t ip_len;

  os_memset(proc_ip, 0, IP_LEN);
  if (netmask_sep) {
    ip_len = strlen(ip) - strlen(netmask_sep);
	os_strlcpy(proc_ip, ip, ip_len + 1);

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
  } else os_strlcpy(proc_ip, ip, IP_LEN);

  errno = 0;
  ret = inet_pton(AF_INET, proc_ip, &(sa.sin_addr));
  if (ret == -1) {
	log_err("inet_pton");
	return false;
  }

  return ret > 0;
}

int ip_2_nbo(char *ip, char *subnet_mask, in_addr_t *addr)
{
  in_addr_t subnet;

  if (addr == NULL) {
	log_trace("addr param is NULL");
	return -1;
  }

  if ((subnet = inet_network(subnet_mask)) == INADDR_NONE) {
	log_trace("Invalid subnet mask address");
	return -1;
  }

  if ((*addr = inet_network(ip)) == INADDR_NONE) {
	log_trace("Invalid ip address");
	return -1;
  }

  *addr = *addr & subnet;

  return 0;
}

int ip4_2_buf(char *ip, uint8_t *buf)
{
  struct in_addr addr;

  if (ip == NULL) {
	  log_trace("ip param is NULL");
	  return -1;
  }

  if (buf == NULL) {
	  log_trace("buf param is NULL");
	  return -1;
  }

  if (!validate_ipv4_string(ip)) {
	  log_trace("IP wroing format");
	  return -1;
  }

  errno = 0;
  if (inet_pton(AF_INET, ip, &addr) < 0) {
	  log_err("inet_pton");
	  return -1;
  }
  
  buf[0] = (uint8_t) (addr.s_addr & 0x000000FF);
  buf[1] = (uint8_t) ((addr.s_addr >> 8) & 0x000000FF);
  buf[2] = (uint8_t) ((addr.s_addr >> 16) & 0x000000FF);
  buf[3] = (uint8_t) ((addr.s_addr >> 24) & 0x000000FF);

  return 0;
}

const char *bit32_2_ip(uint32_t addr, char *ip)
{
  struct in_addr in;
  in.s_addr = addr;
  return inet_ntop(AF_INET, &in, ip, OS_INET_ADDRSTRLEN);
}

const char *inaddr4_2_ip(struct in_addr *addr, char *ip)
{
  return inet_ntop(AF_INET, addr, ip, OS_INET_ADDRSTRLEN);
}

const char *inaddr6_2_ip(struct in6_addr *addr, char *ip)
{
  return inet_ntop(AF_INET6, addr, ip, OS_INET6_ADDRSTRLEN);
}

