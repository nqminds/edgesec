/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file dnsmasq.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of dnsmasq service configuration utilities.
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "dhcp_config.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

bool generate_dnsmasq_conf(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array)
{
  char **p = NULL;
  config_dhcpinfo_t *el = NULL;

  // Delete the config file if present
  int stat = unlink(dconf->dhcp_conf_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(dconf->dhcp_conf_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", dconf->dhcp_conf_path);

  fprintf(fp, "no-resolv\n");
  while(p = (char**)utarray_next(dns_server_array, p)) {
    fprintf(fp, "server=%s\n", *p);
  }

  fprintf(fp, "dhcp-script=%s\n", dconf->dhcp_script_path);
  while(el = (config_dhcpinfo_t *) utarray_next(dconf->config_dhcpinfo_array, el)) {
    if (el->vlanid)
      fprintf(fp, "dhcp-range=%s.%d,%s,%s,%s,%s\n", interface, el->vlanid, el->ip_addr_low, el->ip_addr_upp, el->subnet_mask, el->lease_time);
    else
      fprintf(fp, "dhcp-range=%s,%s,%s,%s,%s\n", interface, el->ip_addr_low, el->ip_addr_upp, el->subnet_mask, el->lease_time);
  }

  fclose(fp);
  return true;
}

bool generate_dnsmasq_script(char *dhcp_script_path, char *domain_server_path)
{
  // Delete the vlan config file if present
  int stat = unlink(dhcp_script_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(dhcp_script_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", dhcp_script_path);

  fprintf(fp, "#!/bin/sh\n");
  fprintf(fp, "str=\"SET_IP $1 $2 $3\"\n");
  fprintf(fp, "echo \"Sending $str ...\"\n");
  fprintf(fp, "echo $str | nc -uU %s -w2 -W1\n", domain_server_path);

  int fd = fileno(fd);

  if (fd == -1) {
    log_err("fileno");
    fclose(fp);
    return false;
  }

  // Make file executable
  
  fclose(fp);
  return true;
}

bool generate_dhcp_configs(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array, char *domain_server_path)
{
  if (!generate_dnsmasq_conf(dconf, interface, dns_server_array))
    return false;
  
  return generate_dnsmasq_script(dconf->dhcp_script_path, domain_server_path);
}