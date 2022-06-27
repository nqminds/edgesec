/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

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
#include "net.h"

bool validate_ipv4_string(char *ip) {
  struct sockaddr_in sa;
  char proc_ip[OS_INET_ADDRSTRLEN];
  char *netmask_sep = strchr(ip, '/');
  int netmask_char_size, ret;
  size_t ip_len;

  os_memset(proc_ip, 0, OS_INET_ADDRSTRLEN);
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
  } else
    os_strlcpy(proc_ip, ip, OS_INET_ADDRSTRLEN);

  errno = 0;
  ret = inet_pton(AF_INET, proc_ip, &(sa.sin_addr));
  if (ret == -1) {
    log_errno("inet_pton");
    return false;
  }

  return ret > 0;
}

int ip_2_nbo(char *ip, char *subnet_mask, in_addr_t *addr) {
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

int ip4_2_buf(char *ip, uint8_t *buf) {
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
    log_trace("IP wrong format");
    return -1;
  }

  errno = 0;
  if (inet_pton(AF_INET, ip, &addr) < 0) {
    log_errno("inet_pton");
    return -1;
  }

  buf[0] = (uint8_t)(addr.s_addr & 0x000000FF);
  buf[1] = (uint8_t)((addr.s_addr >> 8) & 0x000000FF);
  buf[2] = (uint8_t)((addr.s_addr >> 16) & 0x000000FF);
  buf[3] = (uint8_t)((addr.s_addr >> 24) & 0x000000FF);

  return 0;
}

const char *bit32_2_ip(uint32_t addr, char *ip) {
  struct in_addr in;
  in.s_addr = addr;
  return inet_ntop(AF_INET, &in, ip, OS_INET_ADDRSTRLEN);
}

const char *inaddr4_2_ip(struct in_addr *addr, char *ip) {
  return inet_ntop(AF_INET, addr, ip, OS_INET_ADDRSTRLEN);
}

const char *inaddr6_2_ip(struct in6_addr *addr, char *ip) {
  return inet_ntop(AF_INET6, addr, ip, OS_INET6_ADDRSTRLEN);
}

uint8_t get_short_subnet(char *subnet_mask) {
  in_addr_t addr;
  uint8_t short_mask = 0;
  uint32_t shift = 0x80000000U;

  if ((addr = inet_network(subnet_mask)) == INADDR_NONE) {
    log_trace("Invalid subnet mask address");
    return -1;
  }

  for (int i = 0; i < 31; i++) {
    if (addr & shift) {
      short_mask++;
    }

    shift >>= 1U;
  }

  return short_mask;
}

int get_ip_host(char *ip, char *subnet_mask, uint32_t *host) {
  uint8_t ipbuf[4], mbuf[4];

  if (ip4_2_buf(ip, ipbuf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  if (ip4_2_buf(subnet_mask, mbuf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  *host = (uint32_t)((ipbuf[0] << 24) + (ipbuf[1] << 16) + (ipbuf[2] << 8) +
                     ipbuf[3]);
  *host = *host & (uint32_t) ~((mbuf[0] << 24) + (mbuf[1] << 16) +
                               (mbuf[2] << 8) + mbuf[3]);

  return 0;
}

int disable_pmtu_discovery(int sock) {
  int action = IP_PMTUDISC_DONT;
  if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &action, sizeof(action)) <
      0) {
    log_errno("setsockopt");
    return -1;
  }

  return 0;
}

int hwaddr_aton2(const char *txt, uint8_t *addr) {
  int i;
  const char *pos = txt;

  for (i = 0; i < 6; i++) {
    int a, b;

    while (*pos == ':' || *pos == '.' || *pos == '-')
      pos++;

    a = hex2num(*pos++);
    if (a < 0)
      return -1;
    b = hex2num(*pos++);
    if (b < 0)
      return -1;
    *addr++ = (a << 4) | b;
  }

  return pos - txt;
}
