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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>


#include "dhcp_config.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

#define DNSMASQ_BIND_INTERFACE_OPTION "--bind-interfaces"
#define DNSMASQ_NO_DAEMON_OPTION      "--no-daemon"
#define DNSMASQ_LOG_QUERIES_OPTION    "--log-queries"
#define DNSMASQ_CONF_FILE_OPTION      "--conf-file="

bool generate_dnsmasq_conf(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array)
{
  return true;
}

bool generate_dnsmasq_script(char *dhcp_script_path, char *domain_server_path)
{
  return true;
}

bool generate_dhcp_configs(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array, char *domain_server_path)
{
  if (!generate_dnsmasq_conf(dconf, interface, dns_server_array))
    return false;
  
  return generate_dnsmasq_script(dconf->dhcp_script_path, domain_server_path);
}

char* run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  return NULL
}

bool kill_dhcp_process(void)
{
  return true;
}