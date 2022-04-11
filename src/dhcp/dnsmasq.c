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
#include "../utils/squeue.h"
#include "../utils/utarray.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#define DNSMASQ_SERVICE_RESTART       "restart"
#endif

#define PROCESS_RESTART_TIME  5 // In seconds
#define MAX_DHCP_CHECK_COUNT  100 // number of tries

#define DNSMASQ_BIND_INTERFACE_OPTION "--bind-interfaces"
#define DNSMASQ_BIND_DYNAMIC_OPTION   "--bind-dynamic"
#define DNSMASQ_NO_DAEMON_OPTION      "--no-daemon"
#define DNSMASQ_LOG_QUERIES_OPTION    "--log-queries"
#define DNSMASQ_CONF_FILE_OPTION      "--conf-file="

#define DNSMASQ_SCRIPT_STR \
  "#!/bin/sh\n" \
  "sockpath=\"%s\"\n" \
  "str=\"SET_IP $1 $2 $3\"\n" \
  "\n" \
  "nccheck=`nc -help 2>&1 >/dev/null | grep 'OpenBSD netcat'`\n" \
  "if [ -z \"$nccheck\" ]\n" \
  "then\n" \
  "\techo \"Using socat\"\n" \
  "\tcommand=\"socat - UNIX-CLIENT:$sockpath\"\n" \
  "else\n" \
  "\techo \"Using netcat\"\n" \
  "\tcommand=\"nc -uU $sockpath -w2 -W1\"\n" \
  "fi\n" \
  "\n" \
  "echo \"Sending $str ...\"\n" \
  "echo $str | $command\n"

static char dnsmasq_proc_name[MAX_OS_PATH_LEN];
static bool dns_process_started = false;

#ifdef WITH_UCI_SERVICE
struct string_queue* make_interface_list(struct dhcp_conf *dconf)
{
  config_dhcpinfo_t *el = NULL;
  struct string_queue* squeue = init_string_queue(-1);
  char buf[IFNAMSIZ];

  if (squeue == NULL) {
    log_trace("init_string_queue fail");
    return NULL;
  }

  while((el = (config_dhcpinfo_t *) utarray_next(dconf->config_dhcpinfo_array, el)) != NULL) {
    snprintf(buf, IFNAMSIZ, "%s%d", dconf->bridge_prefix, el->vlanid);
    if (push_string_queue(squeue, buf) < 0) {
      log_trace("push_string_queue fail");
      free_string_queue(squeue);
      return NULL;
    }
  }

  return squeue;
}

int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array)
{
  struct string_queue *squeue;
  config_dhcpinfo_t *el = NULL;
  struct uctx *context = uwrt_init_context(NULL);

  if (context == NULL) {
    log_trace("uwrt_init_context fail");
    return -1;
  }

  log_trace("Writing dhcp config using uci");
  if ((squeue = make_interface_list(dconf)) == NULL) {
    log_trace("make_interface_list fail");
    uwrt_free_context(context);
    return -1;
  }

  if (uwrt_gen_dnsmasq_instance(context, squeue, dns_server_array,
                                dconf->dhcp_leasefile_path, dconf->dhcp_script_path) < 0)
  {
    log_trace("uwrt_gen_dnsmasq_instance fail");
    uwrt_free_context(context);
    free_string_queue(squeue);
    return -1;
  }

  while((el = (config_dhcpinfo_t *) utarray_next(dconf->config_dhcpinfo_array, el)) != NULL) {

    if (uwrt_add_dhcp_pool(context, dconf->bridge_prefix, el->vlanid, el->ip_addr_low, el->ip_addr_upp,
                       el->subnet_mask, el->lease_time) < 0)
    {
      log_trace("uwrt_add_dhcp_pool fail");
      uwrt_free_context(context);
      free_string_queue(squeue);
      return -1;
    }
  }

  if (uwrt_commit_section(context, "dhcp") < 0) {
    log_trace("uwrt_commit_section fail");
    uwrt_free_context(context);
    free_string_queue(squeue);
    return -1;
  }

  uwrt_free_context(context);
  free_string_queue(squeue);
  return 0;
}
#else
int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array)
{
  char **p = NULL;
  config_dhcpinfo_t *el = NULL;

  // Delete the config file if present
  int stat = unlink(dconf->dhcp_conf_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return -1;
  }

  FILE *fp = fopen(dconf->dhcp_conf_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return -1;
  }

  log_trace("Writing into %s", dconf->dhcp_conf_path);

  fprintf(fp, "no-resolv\n");
  while((p = (char**)utarray_next(dns_server_array, p)) != NULL) {
    fprintf(fp, "server=%s\n", *p);
  }

  fprintf(fp, "dhcp-leasefile=%s\n", dconf->dhcp_leasefile_path);
  fprintf(fp, "dhcp-script=%s\n", dconf->dhcp_script_path);
  while((el = (config_dhcpinfo_t *) utarray_next(dconf->config_dhcpinfo_array, el)) != NULL) {
    if (el->vlanid)
      fprintf(fp, "dhcp-range=%s.%d,%s,%s,%s,%s\n", dconf->wifi_interface, el->vlanid, el->ip_addr_low, el->ip_addr_upp, el->subnet_mask, el->lease_time);
    else
      fprintf(fp, "dhcp-range=%s,%s,%s,%s,%s\n", dconf->wifi_interface, el->ip_addr_low, el->ip_addr_upp, el->subnet_mask, el->lease_time);
  }

  fclose(fp);
  return 0;
}
#endif

int generate_dnsmasq_script(char *dhcp_script_path, char *domain_server_path)
{
  // Delete the vlan config file if present
  int stat = unlink(dhcp_script_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return -1;
  }

  FILE *fp = fopen(dhcp_script_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return -1;
  }

  log_trace("Writing into %s", dhcp_script_path);

  fprintf(fp, DNSMASQ_SCRIPT_STR, domain_server_path);

  int fd = fileno(fp);

  if (fd == -1) {
    log_err("fileno");
    fclose(fp);
    return -1;
  }

  // Make file executable
  if (make_file_exec_fd(fd) == -1) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

#ifdef WITH_UCI_SERVICE
char* get_dnsmasq_args(char *dnsmasq_bin_path, char *dnsmasq_conf_path, char *argv[])
{
  (void) dnsmasq_conf_path;
  argv[0] = dnsmasq_bin_path;
  argv[1] = DNSMASQ_SERVICE_RESTART;
  return NULL;
}
#else
char* get_dnsmasq_args(char *dnsmasq_bin_path, char *dnsmasq_conf_path, char *argv[])
{
  // sudo dnsmasq --bind-dynamic --no-daemon --log-queries --conf-file=/tmp/dnsmasq.conf
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
  argv[1] = DNSMASQ_BIND_DYNAMIC_OPTION;
  argv[2] = DNSMASQ_NO_DAEMON_OPTION;
  argv[3] = conf_arg;

  return conf_arg;
}
#endif

int check_dhcp_running(char *name, int wait_time)
{
  int running = 0;
  int count = 0;
  while(!running && count < MAX_DHCP_CHECK_COUNT) {
    if ((running = is_proc_running(name)) < 0) {
      log_trace("is_proc_running fail");
      return -1;
    }
    count ++;
    sleep(wait_time);
  }

  return running;
}

#ifdef WITH_UCI_SERVICE
char* run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  pid_t child_pid = 0;
  int ret = 0;
  char *process_argv[3] = {NULL, NULL, NULL};

  os_strlcpy(dnsmasq_proc_name, basename(dhcp_bin_path), MAX_OS_PATH_LEN);

  get_dnsmasq_args(dhcp_bin_path, dhcp_conf_path, process_argv);

  if ((ret = run_process(process_argv, &child_pid)) > 0) {
    log_trace("dnsmasq process exited with status=%d", ret);
    return NULL;
  }

  log_trace("Checking dnsmasq proc running...");
  if (check_dhcp_running(basename(process_argv[0]), 1) <= 0) {
    log_trace("check_dhcp_running or process not running");
    return NULL;
  }

  log_trace("dnsmasq running with pid=%d", child_pid);

  dns_process_started = true;
  return dnsmasq_proc_name;
}
#else
char* run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  pid_t child_pid = 0;
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

  log_trace("Checking dnsmasq proc running...");
  if (check_dhcp_running(basename(process_argv[0]), 1) <= 0) {
    log_trace("check_dhcp_running or process not running");
    return NULL;
  }

  log_trace("dnsmasq running with pid=%d", child_pid);

  dns_process_started = true;
  os_free(conf_arg);
  return dnsmasq_proc_name;
}
#endif

bool kill_dhcp_process(void)
{
  if (dns_process_started) {
    dns_process_started = false;
    return kill_process(dnsmasq_proc_name);
  }

  return true;
}

#ifdef WITH_UCI_SERVICE
int signal_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  (void) dhcp_bin_path;
  (void) dhcp_conf_path;
  return 0;
}
#else
int signal_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path)
{
  char *process_argv[5] = {NULL, NULL, NULL, NULL, NULL};
  char *conf_arg;

  os_strlcpy(dnsmasq_proc_name, basename(dhcp_bin_path), MAX_OS_PATH_LEN);

  if ((conf_arg = get_dnsmasq_args(dhcp_bin_path, dhcp_conf_path, process_argv)) == NULL) {
    log_trace("get_dnsmasq_args fail");
    return -1;
  }

  log_trace("Checking dnsmasq proc running...");
  if (check_dhcp_running(basename(process_argv[0]), 1) <= 0) {
    log_trace("check_dhcp_running or process not running");
    os_free(conf_arg);
    return -1;
  }

  os_free(conf_arg);

  // Signal any running hostapd process to reload the config
  if (!signal_process(dnsmasq_proc_name, SIGHUP)) {
    log_trace("signal_process fail");
    return -1;
  }

  return 0;
}
#endif

int clear_dhcp_lease_entry(char *mac_addr, char *dhcp_leasefile_path)
{
  char *out = NULL, *end = NULL;
  char *start = NULL, *finish = NULL;

  FILE *fp;

  if (mac_addr == NULL) {
    log_trace("mac_addr paramn is NULL");
    return -1;
  }

  if (dhcp_leasefile_path == NULL) {
    log_trace("dhcp_leasefile_path paramn is NULL");
    return -1;
  }

  log_trace("Removing %s from %s", mac_addr, dhcp_leasefile_path);

  if (read_file_string(dhcp_leasefile_path, &out) < 0) {
    log_trace("read_file_string fail");
    return -1;
  }

  if ((start = strstr(out, mac_addr)) == NULL || !strlen(mac_addr)) {
    log_trace("lease entry not found");
    os_free(out);
    return 0;
  }

  finish = start + 1;
  end = out + strlen(out);

  while(start > out) {
    if (*(start - 1) == '\n') {
      break;
    }
    start --;
  }

  *start = '\0';
  while(finish < end) {
    if (*finish == '\n') {
      finish ++;
      break;
    }
    finish ++;
  }

  if ((fp = fopen(dhcp_leasefile_path, "w+")) == NULL) {
    log_err("fopen");
    os_free(out);
    return -1;
  }

  fprintf(fp,"%s%s", out, finish);
  os_free(out);
  fclose(fp);
  return 0;
}