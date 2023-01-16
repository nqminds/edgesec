/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of dnsmasq service configuration
 * utilities.
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

#include "dhcp_config.h"

#include "../utils/allocs.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/squeue.h"

#ifdef WITH_UCI_SERVICE
#include "../utils/uci_wrt.h"
#define DNSMASQ_SERVICE_RESTART "restart"
#endif

#define PROCESS_RESTART_TIME 5   // In seconds
#define MAX_DHCP_CHECK_COUNT 100 // number of tries

#define DNSMASQ_BIND_INTERFACE_OPTION "--bind-interfaces"
#define DNSMASQ_BIND_DYNAMIC_OPTION "--bind-dynamic"
#define DNSMASQ_NO_DAEMON_OPTION "--no-daemon"
#define DNSMASQ_LOG_QUERIES_OPTION "--log-queries"
#define DNSMASQ_CONF_FILE_OPTION "-C"

#define DNSMASQ_SCRIPT_STR                                                     \
  "#!/bin/sh\n"                                                                \
  "sockpath=\"%s\"\n"                                                          \
  "str=\"SET_IP $1 $2 $3\"\n"                                                  \
  "\n"                                                                         \
  "nccheck=`nc -help 2>&1 >/dev/null | grep 'OpenBSD netcat'`\n"               \
  "if [ -z \"$nccheck\" ]\n"                                                   \
  "then\n"                                                                     \
  "\techo \"Using socat\"\n"                                                   \
  "\tcommand=\"socat - UNIX-CLIENT:$sockpath\"\n"                              \
  "else\n"                                                                     \
  "\techo \"Using netcat\"\n"                                                  \
  "\tcommand=\"nc -uU $sockpath -w2 -W1\"\n"                                   \
  "fi\n"                                                                       \
  "\n"                                                                         \
  "echo \"Sending $str ...\"\n"                                                \
  "echo $str | $command\n"

static char dnsmasq_proc_name[MAX_OS_PATH_LEN];
static bool dns_process_started = false;

// The maximum length in chars of a VLAN ID when converted to a decimal string.
// In IEEE 802.1Q, the max VLAN ID is 4094, so 4 characters long in decimal.
static const int MAX_VLANID_CHARS = 4;

int define_dhcp_interface_name(const struct dhcp_conf *dconf, uint16_t vlanid,
                               char *ifname) {
  if (dconf == NULL) {
    log_error("dconf param is NULL");
    return -1;
  }

  if (ifname == NULL) {
    log_error("ifname param is NULL");
    return -1;
  }

#if IF_NAMESIZE < 16
// Make sure that IF_NAMESIZE - 2 - MAX_VLANID_CHARS is always a positive number
#error "Expected IF_NAMESIZE to be at least 16 bytes large"
#endif

#ifdef WITH_UCI_SERVICE
  int snprintf_rc = snprintf(ifname, IF_NAMESIZE, "%.*s%d",
                             IF_NAMESIZE - 1 - MAX_VLANID_CHARS,
                             dconf->bridge_prefix, vlanid);
#else
  int snprintf_rc;
  if (strlen(dconf->wifi_interface)) {
    if (vlanid) {
      snprintf_rc = snprintf(ifname, IF_NAMESIZE, "%.*s.%d",
                             IF_NAMESIZE - 2 - MAX_VLANID_CHARS,
                             dconf->wifi_interface, vlanid);
    } else {
      // should never truncate, since we're writing from a 16-char buffer to a
      // 16-char buffer
      snprintf_rc = snprintf(ifname, IF_NAMESIZE, "%s", dconf->wifi_interface);
    }
  } else {
    // Max VLANID is 4094 = 4 digits
    snprintf_rc = snprintf(ifname, IF_NAMESIZE, "%.*s%d",
                           IF_NAMESIZE - 1 - MAX_VLANID_CHARS,
                           dconf->interface_prefix, vlanid);
  }
#endif
  if (snprintf_rc >= IF_NAMESIZE || snprintf_rc < 0) {
    // this should only happen if vlanid is waaaay too high
    log_error("define_dhcp_interface_name: snprintf error.");
    return -1;
  }
  return 0;
}

#ifdef WITH_UCI_SERVICE
struct string_queue *make_interface_list(struct dhcp_conf *dconf) {
  config_dhcpinfo_t *el = NULL;
  struct string_queue *squeue = init_string_queue(-1);
  char ifname[IF_NAMESIZE];

  if (squeue == NULL) {
    log_error("init_string_queue fail");
    return NULL;
  }

  while ((el = (config_dhcpinfo_t *)utarray_next(dconf->config_dhcpinfo_array,
                                                 el)) != NULL) {

    if (define_dhcp_interface_name(dconf, el->vlanid, ifname) < 0) {
      log_error("define_dhcp_interface_name fail");
      free_string_queue(squeue);
      return NULL;
    }

    if (push_string_queue(squeue, ifname) < 0) {
      log_error("push_string_queue fail");
      free_string_queue(squeue);
      return NULL;
    }
  }

  return squeue;
}

int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array) {
  struct string_queue *squeue;
  config_dhcpinfo_t *el = NULL;
  struct uctx *context = uwrt_init_context(NULL);
  char ifname[IF_NAMESIZE];

  if (context == NULL) {
    log_error("uwrt_init_context fail");
    return -1;
  }

  log_trace("Writing dhcp config using uci");
  if ((squeue = make_interface_list(dconf)) == NULL) {
    log_error("make_interface_list fail");
    uwrt_free_context(context);
    return -1;
  }

  if (uwrt_gen_dnsmasq_instance(context, squeue, dns_server_array,
                                dconf->dhcp_leasefile_path,
                                dconf->dhcp_script_path) < 0) {
    log_error("uwrt_gen_dnsmasq_instance fail");
    uwrt_free_context(context);
    free_string_queue(squeue);
    return -1;
  }

  while ((el = (config_dhcpinfo_t *)utarray_next(dconf->config_dhcpinfo_array,
                                                 el)) != NULL) {

    if (define_dhcp_interface_name(dconf, el->vlanid, ifname) < 0) {
      log_error("define_dhcp_interface_name fail");
      uwrt_free_context(context);
      free_string_queue(squeue);
      return -1;
    }

    if (uwrt_add_dhcp_pool(context, ifname, el->ip_addr_low, el->ip_addr_upp,
                           el->subnet_mask, el->lease_time) < 0) {
      log_error("uwrt_add_dhcp_pool fail");
      uwrt_free_context(context);
      free_string_queue(squeue);
      return -1;
    }
  }

  if (uwrt_commit_section(context, "dhcp") < 0) {
    log_error("uwrt_commit_section fail");
    uwrt_free_context(context);
    free_string_queue(squeue);
    return -1;
  }

  uwrt_free_context(context);
  free_string_queue(squeue);
  return 0;
}
#else
int generate_dnsmasq_conf(struct dhcp_conf *dconf, UT_array *dns_server_array) {
  char **p = NULL;
  config_dhcpinfo_t *el = NULL;
  char ifname[IF_NAMESIZE];

  log_debug("Writing into %s", dconf->dhcp_conf_path);

  FILE *fp = fopen(dconf->dhcp_conf_path, "w");

  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  fprintf(fp, "no-resolv\n");
  while ((p = (char **)utarray_next(dns_server_array, p)) != NULL) {
    fprintf(fp, "server=%s\n", *p);
  }

  fprintf(fp, "dhcp-leasefile=%s\n", dconf->dhcp_leasefile_path);
  fprintf(fp, "dhcp-script=%s\n", dconf->dhcp_script_path);
  while ((el = (config_dhcpinfo_t *)utarray_next(dconf->config_dhcpinfo_array,
                                                 el)) != NULL) {
    if (define_dhcp_interface_name(dconf, el->vlanid, ifname) < 0) {
      log_error("define_dhcp_interface_name fail");
      fclose(fp);
      return -1;
    }

    fprintf(fp, "dhcp-range=%s,%s,%s,%s,%s\n", ifname, el->ip_addr_low,
            el->ip_addr_upp, el->subnet_mask, el->lease_time);
  }

  fclose(fp);
  return 0;
}
#endif

int generate_dnsmasq_script(char *dhcp_script_path,
                            char *supervisor_control_path) {

  log_debug("Writing into %s", dhcp_script_path);

  FILE *fp = fopen(dhcp_script_path, "w");

  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  fprintf(fp, DNSMASQ_SCRIPT_STR, supervisor_control_path);

  int fd = fileno(fp);

  if (fd == -1) {
    log_errno("fileno");
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

/**
 * @brief Builds the `argv` for calling dnsmasq
 *
 * @param dnsmasq_bin_path The path to the dnsmasq binary.
 * @param dnsmasq_conf_path The path to the dnsmasq config file.
 * @param[in,out] argv The array to store the args warning.
 * @pre @p argv must have space for at least 6 pointers.
 */
void get_dnsmasq_args(const char *dnsmasq_bin_path,
                      const char *dnsmasq_conf_path,
                      const char *argv[static 6]) {
#ifdef WITH_UCI_SERVICE
  (void)dnsmasq_conf_path;
  argv[0] = dnsmasq_bin_path;
  argv[1] = DNSMASQ_SERVICE_RESTART;
  argv[2] = NULL;
}
#else
  // sudo dnsmasq --bind-dynamic --no-daemon --log-queries
  // -C /tmp/dnsmasq.conf

  // argv = {"dnsmasq", "--bind-interfaces",
  // "--no-daemon", "--log-queries", "-C", "/tmp/dnsmasq.conf", NULL};
  // argv = {"dnsmasq", "--bind-interfaces", "--no-daemon",
  // "-C", "/tmp/dnsmasq.conf", NULL};
  argv[0] = dnsmasq_bin_path;
  argv[1] = DNSMASQ_BIND_DYNAMIC_OPTION;
  argv[2] = DNSMASQ_NO_DAEMON_OPTION;
  argv[3] = DNSMASQ_CONF_FILE_OPTION;
  argv[4] = dnsmasq_conf_path;
  // should already be NULL
  argv[5] = NULL;
}
#endif

int check_dhcp_running(char *name, int wait_time) {
  int running = 0;
  int count = 0;
  while (!running && count < MAX_DHCP_CHECK_COUNT) {
    if ((running = is_proc_running(name)) < 0) {
      log_error("is_proc_running fail");
      return -1;
    }
    count++;
    sleep(wait_time);
  }

  return running;
}

char *run_dhcp_process(const char *dhcp_bin_path, const char *dhcp_conf_path) {
  const char *process_argv[6] = {NULL};
  get_dnsmasq_args(dhcp_bin_path, dhcp_conf_path, process_argv);

  char *return_val = NULL;

  char **dhcp_argv_modifiable = copy_argv(process_argv);
  if (dhcp_argv_modifiable == NULL) {
    log_errno("Failed to copy_argv for %s", dhcp_bin_path);
    goto error;
  }

  // finds the basename of the dhcp_bin_path and stores it in dnsmasq_proc_name
  {
    // basename() might modify the input string, so make a copy first
    char dnsmasq_proc_name_buffer[MAX_OS_PATH_LEN];
    sys_strlcpy(dnsmasq_proc_name_buffer, dhcp_bin_path, MAX_OS_PATH_LEN - 1);
    dnsmasq_proc_name_buffer[MAX_OS_PATH_LEN - 1] = '\0';
    sys_strlcpy(dnsmasq_proc_name, basename(dnsmasq_proc_name_buffer),
               MAX_OS_PATH_LEN - 1);
  }

  pid_t child_pid = 0;
#ifdef WITH_UCI_SERVICE
  // On OpenWRT with UCI, we just run a `/etc/init.d/dnsmasq restart` command
  int ret = run_process(dhcp_argv_modifiable, &child_pid);
  if (ret > 0) {
    log_error("dnsmasq process exited with status=%d", ret);
    goto error;
  }
#else
  // Otherwise, we create a new `dnsmasq` instance in a background process
  // and kill old dnsmasq process

  // Kill any running dnsmasq process
  if (!kill_process(dnsmasq_proc_name)) {
    log_error("kill_process fail");
    goto error;
  }

  while (true) {
    int ret = run_process(dhcp_argv_modifiable, &child_pid);
    if (ret > 0) {
      log_error("dnsmasq process exited with status=%d", ret);
      goto error;
    }
    if (ret == 0) {
      // success, break out of loop
      break;
    }
    // else (ret < 0)
    log_errno("Error when trying to run dnsmasq process");

    log_trace("Killing dhcp process");
    // Kill any running dnsmasq process
    if (!kill_process(dnsmasq_proc_name)) {
      log_error("kill_process fail");
      goto error;
    }
    log_trace("Restarting process in %d seconds", PROCESS_RESTART_TIME);
    sleep(PROCESS_RESTART_TIME);
  }
#endif
  log_debug("Checking dnsmasq proc running...");
  if (check_dhcp_running(basename(dhcp_argv_modifiable[0]), 1) <= 0) {
    log_error("check_dhcp_running or process not running");
    goto error;
  }

  log_trace("dnsmasq running with pid=%d", child_pid);
  dns_process_started = true;
  return_val = dnsmasq_proc_name;

error:
  free(dhcp_argv_modifiable);
  return return_val;
}

bool kill_dhcp_process(void) {
  if (dns_process_started) {
    dns_process_started = false;
    return kill_process(dnsmasq_proc_name);
  }

  return true;
}

#ifdef WITH_UCI_SERVICE
int signal_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path) {
  (void)dhcp_bin_path;
  (void)dhcp_conf_path;
  return 0;
}
#else
int signal_dhcp_process(char *dhcp_bin_path) {
  sys_strlcpy(dnsmasq_proc_name, basename(dhcp_bin_path), MAX_OS_PATH_LEN);

  // Signal any running dnsmasq process to reload the config
  if (!signal_process(dnsmasq_proc_name, SIGHUP)) {
    log_error("signal_process fail");
    return -1;
  }

  return 0;
}
#endif

int clear_dhcp_lease_entry(char *mac_addr, char *dhcp_leasefile_path) {
  char *out = NULL, *end = NULL;
  char *start = NULL, *finish = NULL;

  FILE *fp;

  if (mac_addr == NULL) {
    log_error("mac_addr paramn is NULL");
    return -1;
  }

  if (dhcp_leasefile_path == NULL) {
    log_error("dhcp_leasefile_path paramn is NULL");
    return -1;
  }

  log_trace("Removing %s from %s", mac_addr, dhcp_leasefile_path);

  if (read_file_string(dhcp_leasefile_path, &out) < 0) {
    log_error("read_file_string fail");
    return -1;
  }

  if ((start = strstr(out, mac_addr)) == NULL || !strlen(mac_addr)) {
    log_trace("lease entry not found");
    os_free(out);
    return 0;
  }

  finish = start + 1;
  end = out + strlen(out);

  while (start > out) {
    if (*(start - 1) == '\n') {
      break;
    }
    start--;
  }

  *start = '\0';
  while (finish < end) {
    if (*finish == '\n') {
      finish++;
      break;
    }
    finish++;
  }

  if ((fp = fopen(dhcp_leasefile_path, "w+")) == NULL) {
    log_errno("fopen");
    os_free(out);
    return -1;
  }

  fprintf(fp, "%s%s", out, finish);
  os_free(out);
  fclose(fp);
  return 0;
}
