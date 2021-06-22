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
 * @file capture_service.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the capture service.
 */
#include <errno.h>

#ifdef WITH_NDPI_SERVICE
#include "ndpi_analyser.h"
#endif

#include "default_analyser.h"
#include "capture_config.h"
#include "capture_service.h"

#include "../utils/log.h"
#include "../utils/os.h"

long get_opt_num(char *port_str)
{
  if (!is_number(port_str))
    return -1;
  
  return strtol(port_str, NULL, 10);
}

int capture_opt2config(char key, char *value, struct capture_conf *config)
{
  switch (key) {
    case 'i':
      os_strlcpy(config->capture_interface, value, IFNAMSIZ);
      break;
    case 'f':
      config->filter = os_malloc(strlen(value) + 1);
      strcpy(config->filter, value);
      break;
    case 'm':
      config->promiscuous = true;
      break;
    case 't':
      config->buffer_timeout = get_opt_num(value);
      if (config->buffer_timeout < 0) {
        return -1;
      }
      break;
    case 'n':
      config->process_interval = get_opt_num(value);
      if (config->process_interval < 0) {
        return -1;
      }
      break;
    case 'y':
      os_strlcpy(config->analyser, value, MAX_ANALYSER_NAME_SIZE);
      if (!strlen(config->analyser)) {
        return -1;
      }
      break;
    case 'e':
      config->immediate = true;
      break;
    case 'u':
      config->file_write = true;
      break;
    case 'w':
      config->db_write = true;
      break;
    case 's':
      config->db_sync = true;
      break;
    case 'q':
      os_strlcpy(config->domain_server_path, value, MAX_OS_PATH_LEN);
      break;
    case 'x':
      os_strlcpy(config->domain_command, value, 64 - 1);
      break;
    case 'z':
      errno = 0;
      config->domain_delim = strtol(value, NULL, 10);
      if (errno == EINVAL || errno == ERANGE || !config->domain_delim)
        return -1;
      break;
    case 'p':
      os_strlcpy(config->db_path, value, MAX_OS_PATH_LEN);
      break;
    case 'a':
      os_strlcpy(config->db_sync_address, value, MAX_WEB_PATH_LEN);
      break;
    case 'o':
      config->db_sync_port = get_opt_num(value);
      if (config->db_sync_port <= 0 || config->db_sync_port > 65535) {
        return -1;
      }
      break;
    default: return 1;
  }

  return 0;
}

char** capture_config2opt(struct capture_conf *config)
{
  char buf[255];
  char **opt_str = (char **)os_malloc((2 * CAPTURE_MAX_OPT) * sizeof(char*));
  int idx = 0;

  if (config == NULL) {
    log_trace("config is NULL");
    return false;
  }

  //capture_bin_path
  if (strlen(config->capture_bin_path)) {
    opt_str[idx] = os_zalloc(strlen(config->capture_bin_path) + 1);
    strcpy(opt_str[idx], config->capture_bin_path);
    idx ++;
  }

  // capture_interface, -i
  if (strlen(config->capture_interface)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-i");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->capture_interface) + 1);
    strcpy(opt_str[idx], config->capture_interface);
    idx ++;
  }

  // filter, -f
  if (strlen(config->filter)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-f");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->filter) + 1);
    strcpy(opt_str[idx], config->filter);
    idx ++;
  }

  // promiscuouse, -m
  if (config->promiscuous) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-m");
    idx ++;
  }

  // buffer_timeout, -t
  sprintf(buf, "%u", config->buffer_timeout);
  opt_str[idx] = os_zalloc(3);
  strcpy(opt_str[idx], "-t");
  idx ++;

  opt_str[idx] = os_zalloc(strlen(buf) + 1);
  strcpy(opt_str[idx], buf);
  idx ++;

  // process_interval, -n
  sprintf(buf, "%u", config->process_interval);
  opt_str[idx] = os_zalloc(3);
  strcpy(opt_str[idx], "-n");
  idx ++;

  opt_str[idx] = os_zalloc(strlen(buf) + 1);
  strcpy(opt_str[idx], buf);
  idx ++;

  // analyser, -y
  if (strlen(config->analyser)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-y");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->analyser) + 1);
    strcpy(opt_str[idx], config->analyser);
    idx ++; 
  }

  //immediate, -e
  if (config->immediate) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-e");
    idx ++;
  }
  //file_write, -u
  if (config->file_write) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-u");
    idx ++;
  }

  //db_write, -w
  if (config->db_write) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-w");
    idx ++;
  }
  //db_sync, -s
  if (config->db_sync) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-s");
    idx ++;
  }

  //domain_server_path, -q
  if (strlen(config->domain_server_path)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-q");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->domain_server_path) + 1);
    strcpy(opt_str[idx], config->domain_server_path);
    idx ++;
  }

  //domain_command, -x
  if (strlen(config->domain_command)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-x");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->domain_command) + 1);
    strcpy(opt_str[idx], config->domain_command);
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

  //db_path, -p
  if (strlen(config->db_path)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-p");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->db_path) + 1);
    strcpy(opt_str[idx], config->db_path);
    idx ++;
  }

  //db_sync_address, -a
  if (strlen(config->db_sync_address)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-a");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(config->db_sync_address) + 1);
    strcpy(opt_str[idx], config->db_sync_address);
    idx ++;
  }

  //db_sync_port, -o
  if (config->db_sync_port) {
    sprintf(buf, "%u", config->db_sync_port);
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-o");
    idx ++;

    opt_str[idx] = os_zalloc(strlen(buf) + 1);
    strcpy(opt_str[idx], buf);
    idx ++;
  }

  opt_str[idx] = NULL;

  return opt_str;
}

void capture_freeopt(char **opt_str)
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

int run_capture(struct capture_conf *config)
{
  if (strcmp(config->analyser, PACKET_ANALYSER_DEFAULT) == 0) {
    log_info("Running default_analyser_engine");
    return start_default_analyser(config);
  } else if (strcmp(config->analyser, PACKET_ANALYSER_NDPI) == 0) {
#ifdef WITH_NDPI_SERVICE
    log_info("Running ndpi_analyser_engine");
    return start_ndpi_analyser(config);
#endif
  }

  return start_default_analyser(config);
}
