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
 * @file dns_config.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of dns service configuration utilities.
 */

#include <errno.h>
// Use to check whether long is same size as uint32_t
#include <limits.h>

#include "dns_config.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

const char* const mdns_description_string = R"--(
  NquiringMinds EDGESEC mdns forwarder.

  Forwards and captures EDGESEC mDNS network traffic for each connected
  device.
  The resulting captured mDNS traffic is forwarded across subnets and bridge commands are issued accordingly.

)--";

int mdns_opt2config(char key, char *value, struct mdns_conf *config)
{
  switch (key) {
    case 'i':
      os_strlcpy(config->capture_interface, value, MAX_CAPIF_LIST_SIZE);
      break;
    case 'f':
      os_strlcpy(config->filter, value, MAX_FILTER_SIZE);
      break;
    case '4':
      config->reflect_ip4 = true;
      break;
    case '6':
      config->reflect_ip6 = true;
      break;
    case 'q':
      os_strlcpy(config->domain_server_path, value, MAX_OS_PATH_LEN);
      break;
    case 'x':
      os_strlcpy(config->domain_command, value, MAX_SUPERVISOR_CMD_SIZE);
      break;
    case 'z':
      errno = 0;
      config->domain_delim = strtol(value, NULL, 10);
      if (errno == EINVAL || errno == ERANGE || !config->domain_delim)
        return -1;
      break;

    default: return 1;
  }

  return 0;
}

char** mdns_config2opt(struct mdns_conf *config)
{
  char buf[255];
  char **opt_str = (char **)os_malloc((2 * MDNS_MAX_OPT) * sizeof(char*));
  int idx = 0;

  if (config == NULL) {
    log_trace("config is NULL");
    return false;
  }

  // capture_interface, -i
  if (os_strnlen_s(config->capture_interface, MAX_CAPIF_LIST_SIZE)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-i");
    idx ++;

    opt_str[idx] = os_malloc(MAX_CAPIF_LIST_SIZE);
    os_strlcpy(opt_str[idx], config->capture_interface, IFNAMSIZ);
    idx ++;
  }

  // filter, -f
  if (os_strnlen_s(config->filter, MAX_FILTER_SIZE)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-f");
    idx ++;

    opt_str[idx] = os_malloc(MAX_FILTER_SIZE);
    os_strlcpy(opt_str[idx], config->filter, MAX_FILTER_SIZE);
    idx ++;
  }

  //domain_server_path, -q
  if (os_strnlen_s(config->domain_server_path, MAX_OS_PATH_LEN)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-q");
    idx ++;

    opt_str[idx] = os_malloc(MAX_OS_PATH_LEN);
    os_strlcpy(opt_str[idx], config->domain_server_path, MAX_OS_PATH_LEN);
    idx ++;
  }

  //domain_command, -x
  if (os_strnlen_s(config->domain_command, MAX_SUPERVISOR_CMD_SIZE)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-x");
    idx ++;

    opt_str[idx] = os_malloc(MAX_SUPERVISOR_CMD_SIZE);
    os_strlcpy(opt_str[idx], config->domain_command, MAX_SUPERVISOR_CMD_SIZE);
    idx ++;
  }

  //domain_delim, -z
  if (config->domain_delim) {
    sprintf(buf, "%d", config->domain_delim);
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-z");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(buf) + 1);
    strcpy(opt_str[idx], buf);
    idx ++;
  }

  //reflect_ip4, -4
  if (config->reflect_ip4) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-4");
    idx ++;
  }

  //reflect_ip6, -6
  if (config->reflect_ip6) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-6");
    idx ++;
  }

  opt_str[idx] = NULL;

  return opt_str;
}

void mdns_freeopt(char **opt_str)
{
  int idx = 0;
  if (opt_str != NULL) {
    while(opt_str[idx] != NULL) {
      os_free(opt_str[idx]);
      idx ++;
    }
    os_free(opt_str);
  }
}
