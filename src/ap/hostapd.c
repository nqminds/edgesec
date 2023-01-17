/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of hostapd config generation
 * utilities.
 *
 * Defines function that generate the hostapd daemon configuration file and
 * manages (execute, kill and signal) the hostapd process.
 */

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ap_config.h"
#include "utils/allocs.h"
#include "utils/iface.h"
#include "utils/log.h"
#include "utils/os.h"

#define WITH_HOSTAPD_UCI

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#define HOSTAPD_SERVICE_RELOAD "reload"
#define HOSTAPD_PROCESS_NAME "hostapd"
#endif

#define HOSTAPD_LOG_FILE_OPTION "-f"

#define PROCESS_RESTART_TIME 5 /* In seconds */
#define MAX_AP_CHECK_COUNT 5   /* Number of tries */

static char hostapd_proc_name[MAX_OS_PATH_LEN];
static bool ap_process_started = false;

int generate_vlan_conf(char *vlan_file, char *interface) {

  log_debug("Writing into %s", vlan_file);

  FILE *fp = fopen(vlan_file, "w");

  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  fprintf(fp, "*\t%s.#\n", interface);

  fclose(fp);
  return 0;
}

#if (defined(WITH_UCI_SERVICE) && defined(WITH_HOSTAPD_UCI))
int generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf) {
  struct hostapd_params params;
  struct uctx *context = uwrt_init_context(NULL);

  if (context == NULL) {
    log_error("uwrt_init_context fail");
    return -1;
  }

  log_debug("Writing hostapd config using uci");

  params.device = hconf->device;
  params.auth_algs = hconf->auth_algs;
  params.wpa = hconf->wpa;
  params.wpa_key_mgmt = hconf->wpa_key_mgmt;
  params.ieee8021x = hconf->ieee8021x;
  params.rsn_pairwise = hconf->rsn_pairwise;
  params.radius_client_ip = rconf->radius_client_ip;
  params.radius_server_ip = rconf->radius_server_ip;
  params.radius_port = rconf->radius_port;
  params.radius_secret = rconf->radius_secret;
  params.macaddr_acl = hconf->macaddr_acl;
  params.dynamic_vlan = hconf->dynamic_vlan;
  params.vlan_file = hconf->vlan_file;
  params.ignore_broadcast_ssid = hconf->ignore_broadcast_ssid;
  params.wpa_psk_radius = hconf->wpa_psk_radius;
  params.vlan_bridge = hconf->vlan_bridge;
  params.ssid = hconf->ssid;
  params.wpa_passphrase = hconf->wpa_passphrase;

  if (uwrt_gen_hostapd_instance(context, &params) < 0) {
    log_error("uwrt_gen_hostapd_instance fail");
    uwrt_free_context(context);
    return -1;
  }

  if (uwrt_commit_section(context, "wireless") < 0) {
    log_error("uwrt_commit_section fail");
    uwrt_free_context(context);
    return -1;
  }

  uwrt_free_context(context);
  return 0;
}
#else
int generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf) {
  log_debug("Writing into %s", hconf->ap_file_path);

  FILE *fp = fopen(hconf->ap_file_path, "w");
  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  fprintf(fp, "interface=%s\n", hconf->interface);
  fprintf(fp, "driver=%s\n", hconf->driver);
  fprintf(fp, "ssid=%s\n", hconf->ssid);
  fprintf(fp, "hw_mode=%s\n", hconf->hw_mode);
  fprintf(fp, "channel=%d\n", hconf->channel);
  fprintf(fp, "wmm_enabled=%d\n", hconf->wmm_enabled);
  fprintf(fp, "auth_algs=%d\n", hconf->auth_algs);
  fprintf(fp, "wpa=%d\n", hconf->wpa);
  fprintf(fp, "wpa_key_mgmt=%s\n", hconf->wpa_key_mgmt);
  fprintf(fp, "ieee8021x=%d\n", hconf->ieee8021x);
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
  return 0;
}
#endif

void get_hostapd_args(const char *hostapd_bin_path,
                      const char *hostapd_file_path,
                      const char *hostapd_log_path,
                      const char *argv[static 5]) {
#if (defined(WITH_UCI_SERVICE) && defined(WITH_HOSTAPD_UCI))
  (void)hostapd_file_path;
  (void)hostapd_log_path;

  argv[0] = hostapd_bin_path;
  argv[1] = HOSTAPD_SERVICE_RELOAD;
  argv[2] = NULL;
#else
  // argv = {"hostapd", "-B", hostapd_file_path, NULL};
  // argv = {"hostapd", hostapd_file_path, NULL};

  argv[0] = hostapd_bin_path;
  if (strlen(hostapd_log_path)) {
    argv[1] =
        HOSTAPD_LOG_FILE_OPTION; /* ./hostapd -f hostapd.log hostapd.conf */
    argv[2] = hostapd_log_path;
    argv[3] = hostapd_file_path;
    argv[4] = NULL;
  } else {
    argv[1] = hostapd_file_path; /* ./hostapd hostapd.conf */
    argv[2] = NULL;
  }
#endif
}

int check_ap_running(char *name, char *if_name, int wait_time) {
  int running = 0;
  int count = 0;

  while ((!running || check_sock_file_exists(if_name) < 0) &&
         count < MAX_AP_CHECK_COUNT) {
    if ((running = is_proc_running(name)) < 0) {
      log_error("is_proc_running fail");
      return -1;
    }
    count++;
    sleep(wait_time);
  }

  return running;
}

int run_ap_process(struct apconf *hconf) {
  pid_t child_pid = 0;
  const char *process_argv[5] = {NULL};
  get_hostapd_args(hconf->ap_bin_path, hconf->ap_file_path, hconf->ap_log_path,
                   process_argv);

  int return_code = -1;

  char **argv_copy = copy_argv(process_argv);
  if (argv_copy == NULL) {
    log_errno("Failed to copy_argv for %s", hconf->ap_bin_path);
    goto cleanup;
  }

#if (defined(WITH_UCI_SERVICE) && defined(WITH_HOSTAPD_UCI))
  os_strlcpy(hostapd_proc_name, HOSTAPD_PROCESS_NAME, MAX_OS_PATH_LEN);

  int ret = run_process(argv_copy, &child_pid);
  if (ret < 0) {
    log_error("hostapd process exited with status=%d", ret);
    goto cleanup;
  }

  log_trace("Checking ap proc running...");
  ret = check_ap_running(hostapd_proc_name, hconf->ctrl_interface_path, 1);
  if (ret < 0) {
    log_error("check_ap_running fail");
    goto cleanup;
  } else if (ret == 0) {
    log_error("hostapd not running");
    goto cleanup;
  }

  log_trace("hostapd instance running");
#else
  char ap_bin_path_copy[MAX_OS_PATH_LEN];
  os_strlcpy(ap_bin_path_copy, hconf->ap_bin_path, MAX_OS_PATH_LEN);
  os_strlcpy(hostapd_proc_name, basename(ap_bin_path_copy), MAX_OS_PATH_LEN);

  // Kill any running hostapd process
  if (!kill_process(hostapd_proc_name)) {
    log_trace("kill_process fail");
    return -1;
  }

  int ret;
  while ((ret = run_process(argv_copy, &child_pid)) < 0) {
    log_trace("Killing hostapd process");
    // Kill any running hostapd process
    if (!kill_process(hostapd_proc_name)) {
      log_error("kill_process fail");
      return -1;
    }
    log_trace("Restarting process in %d seconds", PROCESS_RESTART_TIME);
    sleep(PROCESS_RESTART_TIME);
  }

  if (ret > 0) {
    log_error("hostapd process exited with status=%d", ret);
    return -1;
  }

  log_trace("hostapd instance running (pid=%d)", child_pid);
#endif
  ap_process_started = true;
  return_code = 0;
cleanup:
  free(argv_copy);
  return return_code;
}

bool kill_ap_process(void) {
  // Kill any running hostapd process
  if (ap_process_started) {
    ap_process_started = false;
    return kill_process(hostapd_proc_name);
  }

  return true;
}

int signal_ap_process(const struct apconf *hconf) {
  char ap_bin_path_copy[MAX_OS_PATH_LEN];
  os_strlcpy(ap_bin_path_copy, hconf->ap_bin_path, MAX_OS_PATH_LEN);
  os_strlcpy(hostapd_proc_name, basename(ap_bin_path_copy), MAX_OS_PATH_LEN);

  // Signal any running hostapd process to reload the config
  if (!signal_process(hostapd_proc_name, SIGHUP)) {
    log_error("signal_process fail");
    return -1;
  }

  return 0;
}
