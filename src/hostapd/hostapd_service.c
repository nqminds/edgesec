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
 * @file hostapd_service.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the hostapd service.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>

#include "hostapd_config.h"
#include "radius/radius_server.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/log.h"

#define HOSTAPD_LOG_FILE_OPTION "-f"

#define PROCESS_RESTART_TIME  5 // In seconds

void get_hostapd_args(char *hostapd_bin_path, char *hostapd_file_path, char *hostapd_log_path, char *argv[])
{
  // argv = {"hostapd", "-B", hostapd_file_path, NULL};
  // argv = {"hostapd", hostapd_file_path, NULL};

  argv[0] = hostapd_bin_path;
  if (strlen(hostapd_log_path)) {
    argv[1] = HOSTAPD_LOG_FILE_OPTION;  /* ./hostapd -f hostapd.log hostapd.conf */
    argv[2] = hostapd_log_path;
    argv[3] = hostapd_file_path;
  } else {
    argv[1] = hostapd_file_path;        /* ./hostapd hostapd.conf */
  }
}

int check_ctrl_if_exists(char *ctrl_if_path)
{
  struct stat sb;

  if (stat(ctrl_if_path, &sb) == -1) {
    log_err("stat %s", ctrl_if_path);
    return -1;
  }

  if ((sb.st_mode & S_IFMT) != S_IFSOCK)
    return -1;

  return 0;
}

int run_hostapd(struct hostapd_conf *hconf, struct radius_conf *rconf, bool exec_hostapd, char *ctrl_if_path)
{
  int ret;
  char *proc_name = basename(hconf->hostapd_bin_path);

  char *process_argv[5] = {NULL, NULL, NULL, NULL, NULL};
  get_hostapd_args(hconf->hostapd_bin_path, hconf->hostapd_file_path, hconf->hostapd_log_path, process_argv);

  if (!generate_vlan_conf(hconf->vlan_file, hconf->interface)) {
    log_trace("generate_vlan_conf fail");
    return -1;
  }

  if (!generate_hostapd_conf(hconf, rconf)) {
    unlink(hconf->vlan_file);
    log_trace("generate_hostapd_conf fail");
    return -1;
  }

  if (exec_hostapd) {
    // Kill any running hostapd process
    if (!kill_process(proc_name)) {
      log_trace("kill_process fail");
      return -1;
    }

    while((ret = run_process(process_argv)) > 0) {
      log_trace("Killing hostapd process");

      // Kill any running hostapd process
      if (!kill_process(proc_name)) {
        log_trace("kill_process fail");
        return -1;
      }

      log_trace("Restarting process in %d seconds", PROCESS_RESTART_TIME);
      sleep(PROCESS_RESTART_TIME);
    }

    if (ret != 0) {
      log_trace("run_process fail");
      return -1;
    }

    if (check_ctrl_if_exists(ctrl_if_path) != -1) {
      log_trace("hostapd unix domain control path %s", ctrl_if_path);
    } else {
      log_trace("hostapd unix domain control path fail");
      return -1;    
    }
  }

  return 0;
}

bool close_hostapd(int sock)
{
  // Kill any running hostapd process
  if (!kill_process("hostapd")) {
    log_trace("kill_process fail");
    return false;
  }

  return true;
}
