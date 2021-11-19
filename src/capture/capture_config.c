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
 * @file capture_config.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the capture config structures.
 */
#include <errno.h>
// Use to check whether long is same size as uint32_t
#include <limits.h>

#include "capture_config.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

const char* const capture_description_string = R"--(
  NquiringMinds EDGESEC capture server.

  Monitors and captures EDGESEC network traffic for each connected
  device.
  The resulting traffic analytics is sent to the network controller
  for device management.

  EDGESec can be run in two different modes:
    - Capture Mode:
      Pass [-y engine] to enable capture mode.
    - Cleaning Mode:
      Pass [-b SIZE] to enable cleaning mode
      The capture server will wait until SIZE KiB of PCAP data has been
      saved. Then it will cleanup the PCAP data.
)--";

long get_opt_num(char *num)
{
  if (!is_number(num))
    return -1;
  
  return strtol(num, NULL, 10);
}

int process_sync_params(char *param_str, struct capture_conf *config)
{
  char **p = NULL;
  UT_array *param_arr;
  utarray_new(param_arr, &ut_str_icd);

  if (split_string_array(param_str, ',', param_arr) < 0) {
    utarray_free(param_arr);
    return -1;
  }

  if (utarray_len(param_arr) < 2) {
    utarray_free(param_arr);
    return -1;
  }

  errno = 0;
  p = (char**) utarray_next(param_arr, p);
  if (*p != NULL) {
    if (os_strnlen_s(*p, 9) && is_number(*p)) {
      config->sync_store_size = strtol(*p, NULL, 10);
      if (errno == EINVAL) {
        utarray_free(param_arr);
        return -1;
      }
    } else {
      utarray_free(param_arr);
      return -1;
    }
  } else {
    utarray_free(param_arr);
    return -1;
  }

  errno = 0;
  p = (char**) utarray_next(param_arr, p);
  if (*p != NULL) {
    if (os_strnlen_s(*p, 9) && is_number(*p)) {
      config->sync_send_size = strtol(*p, NULL, 10);
      if (errno == EINVAL) {
        utarray_free(param_arr);
        return -1;
      }
    } else {
      utarray_free(param_arr);
      return -1;
    }
  } else {
    utarray_free(param_arr);
    return -1;
  }

  utarray_free(param_arr);
  return 0;
}

int capture_opt2config(char key, char *value, struct capture_conf *config)
{
  long conversion;
  switch (key) {
    case 'i':
      os_strlcpy(config->capture_interface, value, MAX_CAPIF_LIST_SIZE);
      break;
    case 'f':
      os_strlcpy(config->filter, value, MAX_FILTER_SIZE);
      break;
    case 'm':
      config->promiscuous = true;
      break;
    case 't':
      conversion = get_opt_num(value);
      if (conversion < 0) {
        return -1;
      }

      config->buffer_timeout = (uint32_t) conversion;
      break;
    case 'n':
      conversion = get_opt_num(value);
      if (conversion < 0) {
        return -1;
      }

      config->process_interval = (uint32_t) conversion;
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
      os_strlcpy(config->domain_command, value, MAX_SUPERVISOR_CMD_SIZE);
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
    case 'k':
      os_strlcpy(config->ca_path, value, MAX_OS_PATH_LEN);
      break;
    case 'o':
      conversion = get_opt_num(value);
      if (conversion <= 0 || conversion > 65535) {
        return -1;
      }

      config->db_sync_port = (uint16_t) conversion;
      break;
    case 'r':
      if (process_sync_params(value, config) < 0) {
        return -1;
      }
      break;
    case 'b':
      conversion = get_opt_num(value);
      if (conversion < 0) {
        return -1;
      }
      if (UINT32_MAX != ULONG_MAX && conversion > UINT32_MAX) {
        log_err("Overflow, byte size %s exceeds uint32", value);
        return -1;
      }

      config->capture_store_size = (uint32_t) conversion;
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
  if (os_strnlen_s(config->capture_bin_path, MAX_OS_PATH_LEN)) {
    opt_str[idx] = os_malloc(MAX_OS_PATH_LEN);
    os_strlcpy(opt_str[idx], config->capture_bin_path, MAX_OS_PATH_LEN);
    idx ++;
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
  if (os_strnlen_s(config->analyser, MAX_ANALYSER_NAME_SIZE)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-y");
    idx ++;

    opt_str[idx] = os_malloc(MAX_ANALYSER_NAME_SIZE);
    os_strlcpy(opt_str[idx], config->analyser, MAX_ANALYSER_NAME_SIZE);
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

  //db_path, -p
  if (os_strnlen_s(config->db_path, MAX_OS_PATH_LEN)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-p");
    idx ++;

    opt_str[idx] = os_malloc(MAX_OS_PATH_LEN);
    os_strlcpy(opt_str[idx], config->db_path, MAX_OS_PATH_LEN);
    idx ++;
  }

  //db_sync_address, -a
  if (strlen(config->db_sync_address)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-a");
    idx ++;

    opt_str[idx] = os_malloc(MAX_WEB_PATH_LEN);
    os_strlcpy(opt_str[idx], config->db_sync_address, MAX_WEB_PATH_LEN);
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

  //ca_path, -k
  if (strlen(config->ca_path)) {
    opt_str[idx] = os_zalloc(3);
    strcpy(opt_str[idx], "-k");
    idx ++;

    opt_str[idx] = os_malloc(MAX_OS_PATH_LEN);
    os_strlcpy(opt_str[idx], config->ca_path, MAX_OS_PATH_LEN);
    idx ++;
  }

  //sync params, -r
  sprintf(buf, "%ld,%ld", config->sync_store_size, config->sync_send_size);
  opt_str[idx] = os_zalloc(3);
  strcpy(opt_str[idx], "-r");
  idx ++;

  opt_str[idx] = os_zalloc(strlen(buf) + 1);
  strcpy(opt_str[idx], buf);
  idx ++;

  //capture_store_size, -b
  sprintf(buf, "%u", config->capture_store_size);
  opt_str[idx] = os_zalloc(3);
  strcpy(opt_str[idx], "-b");
  idx ++;

  opt_str[idx] = os_zalloc(strlen(buf) + 1);
  strcpy(opt_str[idx], buf);
  idx ++;

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
