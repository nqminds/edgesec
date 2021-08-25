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
 * @file hostapd.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of hostapd config generation utilities.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>

#include "ap_config.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/if.h"

#define HOSTAPD_LOG_FILE_OPTION "-f"

#define PROCESS_RESTART_TIME  5 // In seconds

static char hostapd_proc_name[MAX_OS_PATH_LEN];
static bool ap_process_started = false;

bool generate_vlan_conf(char *vlan_file, char *interface)
{
  // Delete the vlan config file if present
  int stat = unlink(vlan_file);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(vlan_file, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", vlan_file);

  fprintf(fp, "*\t%s.#\n", interface);

  fclose(fp);
  return true;
}

bool generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf)
{
  // Delete the config file if present
  int stat = unlink(hconf->ap_file_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(hconf->ap_file_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", hconf->ap_file_path);

  fprintf(fp, "interface=%s\n", hconf->interface);
  fprintf(fp, "bridge=%s\n", hconf->bridge);
  fprintf(fp, "driver=%s\n", hconf->driver);
  fprintf(fp, "ssid=%s\n", hconf->ssid);
  fprintf(fp, "hw_mode=%s\n", hconf->hw_mode);
  fprintf(fp, "channel=%d\n", hconf->channel);
  fprintf(fp, "wmm_enabled=%d\n", hconf->wmm_enabled);
  fprintf(fp, "auth_algs=%d\n", hconf->auth_algs);
  fprintf(fp, "wpa=%d\n", hconf->wpa);
  fprintf(fp, "wpa_key_mgmt=%s\n", hconf->wpa_key_mgmt);
  fprintf(fp, "rsn_pairwise=%s\n", hconf->rsn_pairwise);
  fprintf(fp, "ctrl_interface=%s\n", hconf->ctrl_interface);
  fprintf(fp, "own_ip_addr=%s\n", rconf->radius_client_ip);
  fprintf(fp, "auth_server_addr=%s\n", rconf->radius_server_ip);
  fprintf(fp, "auth_server_port=%d\n", rconf->radius_port);
  fprintf(fp, "auth_server_shared_secret=%s\n", rconf->radius_secret);
  fprintf(fp, "macaddr_acl=%d\n", hconf->macaddr_acl);
  fprintf(fp, "dynamic_vlan=%d\n", hconf->dynamic_vlan);
  fprintf(fp, "vlan_bridge=%s\n", hconf->vlan_bridge);
  fprintf(fp, "vlan_file=%s\n", hconf->vlan_file);
  fprintf(fp, "logger_stdout=%d\n", hconf->logger_stdout);
  fprintf(fp, "logger_stdout_level=%d\n", hconf->logger_stdout_level);
  fprintf(fp, "logger_syslog=%d\n", hconf->logger_syslog);
  fprintf(fp, "logger_syslog_level=%d\n", hconf->logger_syslog_level);
  fprintf(fp, "ignore_broadcast_ssid=%d\n", hconf->ignore_broadcast_ssid);
  fprintf(fp, "wpa_psk_radius=%d\n", hconf->wpa_psk_radius);
  if (strlen(hconf->vlan_tagged_interface)) {
    fprintf(fp, "vlan_naming=1\n");
    fprintf(fp, "vlan_tagged_interface=%s\n", hconf->vlan_tagged_interface);
  }
  fclose(fp);
  return true;
}

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

int run_ap_process(struct apconf *hconf, char *ctrl_if_path)
{
  pid_t child_pid;
  int ret, check_count = 0;
  char *process_argv[5] = {NULL, NULL, NULL, NULL, NULL};

  os_strlcpy(hostapd_proc_name, basename(hconf->ap_bin_path), MAX_OS_PATH_LEN);

  get_hostapd_args(hconf->ap_bin_path, hconf->ap_file_path, hconf->ap_log_path, process_argv);
  struct find_dir_type dir_args = {.proc_running = 0, .proc_name = basename(process_argv[0])};

  // Kill any running hostapd process
  if (!kill_process(hostapd_proc_name)) {
    log_trace("kill_process fail");
    return -1;
  }

  log_trace("Resetting wifi interface %s", hconf->interface);
  if (!reset_interface(hconf->interface)) {
    log_debug("reset_interface fail");
    return -1;
  }

  while((ret = run_process(process_argv, &child_pid)) < 0) {
    log_trace("Killing hostapd process");
    // Kill any running hostapd process
    if (!kill_process(hostapd_proc_name)) {
      log_trace("kill_process fail");
      return -1;
    }
    log_trace("Restarting process in %d seconds", PROCESS_RESTART_TIME);
    sleep(PROCESS_RESTART_TIME);
  }

  if (ret > 0) {
    log_trace("hostapd process exited with status=%d", ret);
    return -1;
  }

  if (list_dir("/proc", find_dir_proc_fn, (void *)&dir_args) == -1) {
    log_trace("list_dir fail");
    return -1;
  }

  if (!dir_args.proc_running) {
    log_trace("hostapd proc not found");
  }

  log_trace("hostapd running with pid=%d", child_pid);

  while (check_count++ < 7) {
    if (check_sock_file_exists(ctrl_if_path) != -1) {
      log_trace("hostapd unix domain control path %s", ctrl_if_path);
      break;
    } else {
      log_trace("hostapd unix domain control path check try=%d", check_count);
    }
    sleep(2);
  }

  if (check_count >= 7) {
    log_trace("hostapd unix domain control path fail");
    return -1;
  }

  ap_process_started = true;
  return 0;
}

bool kill_ap_process(void)
{
  // Kill any running hostapd process
  if (ap_process_started) {
    ap_process_started = false;
    return kill_process(hostapd_proc_name);
  }

  return true;
}

int signal_ap_process(char *ap_bin_path)
{
  os_strlcpy(hostapd_proc_name, basename(ap_bin_path), MAX_OS_PATH_LEN);

  // Signal any running hostapd process to reload the config
  if (!signal_process(hostapd_proc_name, SIGHUP)) {
    log_trace("signal_process fail");
    return -1;
  }

  return 0;
}
