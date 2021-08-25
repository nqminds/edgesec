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
#include "../utils/allocs.h"
#include "../utils/os.h"
#include "../utils/utarray.h"

#define PROCESS_RESTART_TIME  5 // In seconds

#define DNSMASQ_BIND_INTERFACE_OPTION "--bind-interfaces"
#define DNSMASQ_NO_DAEMON_OPTION      "--no-daemon"
#define DNSMASQ_LOG_QUERIES_OPTION    "--log-queries"
#define DNSMASQ_CONF_FILE_OPTION      "--conf-file="

static char dnsmasq_proc_name[MAX_OS_PATH_LEN];
static bool dns_process_started = false;

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

  int fd = fileno(fp);

  if (fd == -1) {
    log_err("fileno");
    fclose(fp);
    return false;
  }

  // Make file executable
  if (make_file_exec_fd(fd) == -1) {
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
}

bool generate_dhcp_configs(struct dhcp_conf *dconf, char *interface, UT_array *dns_server_array, char *domain_server_path)
{
  if (!generate_dnsmasq_conf(dconf, interface, dns_server_array))
    return false;
  
  return generate_dnsmasq_script(dconf->dhcp_script_path, domain_server_path);
}

char* get_dnsmasq_args(char *dnsmasq_bin_path, char *dnsmasq_conf_path, char *argv[])
{
  // sudo dnsmasq --bind-interfaces --no-daemon --log-queries --conf-file=/tmp/dnsmasq.conf
  // argv = {"dnsmasq", "--bind-interfaces", "--no-daemon", "--log-queries", "--conf-file=/tmp/dnsmasq.conf", NULL};
  // argv = {"dnsmasq", "--bind-interfaces", "--no-daemon", "--conf-file=/tmp/dnsmasq.conf", NULL};

  if (os_strnlen_s(dnsmasq_conf_path, MAX_OS_PATH_LEN) >= MAX_OS_PATH_LEN) {
    log_trace("dnsmasq_conf_path exceeds/is MAX length");
    return NULL;
  }

  char *conf_arg = os_malloc(sizeof(char)*(MAX_OS_PATH_LEN + strlen(DNSMASQ_CONF_FILE_OPTION) + 1));

  if (conf_arg == NULL) {
    log_err("os_malloc");
    return NULL;
  }

  conf_arg[0] = '\0';
  strcat(conf_arg, DNSMASQ_CONF_FILE_OPTION);
  strcat(conf_arg, dnsmasq_conf_path);

  argv[0] = dnsmasq_bin_path;
  argv[1] = DNSMASQ_BIND_INTERFACE_OPTION;
  argv[2] = DNSMASQ_NO_DAEMON_OPTION;
  argv[3] = conf_arg;

  return conf_arg;
}

char* run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  pid_t child_pid;
  int ret;
  char *process_argv[5] = {NULL, NULL, NULL, NULL, NULL};

  os_strlcpy(dnsmasq_proc_name, basename(dhcp_bin_path), MAX_OS_PATH_LEN);

  // Kill any running hostapd process
  if (!kill_process(dnsmasq_proc_name)) {
    log_trace("kill_process fail");
    return NULL;
  }

  char *conf_arg = get_dnsmasq_args(dhcp_bin_path, dhcp_conf_path, process_argv);

  if (conf_arg == NULL) {
    log_trace("get_dnsmasq_args fail");
    return NULL;
  }
  struct find_dir_type dir_args = {.proc_running = 0, .proc_name = basename(process_argv[0])};

  while((ret = run_process(process_argv, &child_pid)) < 0) {
    log_trace("Killing dhcp process");
    // Kill any running hostapd process
    if (!kill_process(dnsmasq_proc_name)) {
      log_trace("kill_process fail");
      os_free(conf_arg);
      return NULL;
    }
    log_trace("Restarting process in %d seconds", PROCESS_RESTART_TIME);
    sleep(PROCESS_RESTART_TIME);
  }

  if (ret > 0) {
    log_trace("dnsmasq process exited with status=%d", ret);
    os_free(conf_arg);
    return NULL;
  }

  if (list_dir("/proc", find_dir_proc_fn, (void *)&dir_args) == -1) {
    log_trace("list_dir fail");
    os_free(conf_arg);
    return NULL;
  }

  if (!dir_args.proc_running) {
    log_trace("dnsmasq proc not found");
  }

  log_trace("dnsmasq running with pid=%d", child_pid);

  dns_process_started = true;
  os_free(conf_arg);
  return dnsmasq_proc_name;
}

bool kill_dhcp_process(void)
{
  if (dns_process_started) {
    dns_process_started = false;
    return kill_process(dnsmasq_proc_name);
  }

  return true;
}