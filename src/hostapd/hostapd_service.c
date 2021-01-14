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

#include "config_generator.h"
#include "radius/radius_server.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/log.h"

long is_hostapd(char *path)
{
  char exe_path[MAX_OS_PATH_LEN];
  char resolved_path[MAX_OS_PATH_LEN];

  unsigned long pid = strtoul(basename(path), NULL, 10);

  if (errno != ERANGE && pid != 0L) {
    snprintf(exe_path, MAX_OS_PATH_LEN - 1, "%s/exe", path);
    if (realpath(exe_path, resolved_path) != NULL) {
      if (strcmp(basename(resolved_path), "hostapd") == 0) {
        return pid;
      }
    }
  }

  return 0;
}

void kill_dir_fn(char *path, void *args)
{
  unsigned long pid;
  if ((pid = is_hostapd(path)) != 0) {
    if (kill(pid, SIGKILL) == -1)
      log_err("kill");
    else
      log_trace("killed hostapd process with pid=%d",pid);
  }
}

void find_dir_fn(char *path, void *args)
{
  unsigned long pid;
  int *is_h = args;

  if ((pid = is_hostapd(path)) != 0)
    *is_h = 1;
  else
    *is_h = 0;
}

int run_process(char *hostapd_bin_path, char *hostapd_file_path)
{
  pid_t child_pid, ret;
  int status, check_count = 0;

  // char *argv[4] = {"hostapd", "-B", hostapd_file_path, NULL};
  char *argv[3] = {"hostapd", hostapd_file_path, NULL};

  log_trace("Running hostapd process %s", hostapd_bin_path);
  log_trace("\t with params %s %s", argv[1], argv[2]);

  switch (child_pid = fork()) {
  case -1:            /* fork() failed */
    log_err("fork");
    return -1;

  case 0:                           /* Child: exec command */
    /* redirect stdout, stdin and stderr to /dev/null */
    close(STDIN_FILENO);

    /* Reopen standard fd's to /dev/null */
    int fd = open("/dev/null", O_RDWR);

    if (fd != STDIN_FILENO)         /* 'fd' should be 0 */
      return -1;
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
      return -1;
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
      return -1;

    execv(hostapd_bin_path, argv);

    log_err("execv");
    return -1;       /* We could not exec the command */
  default:
    log_trace("hostapd child created with id=%d", child_pid);
    log_trace("Checking hostapd execution status...");
    while ((ret = waitpid(child_pid, &status, WNOHANG)) == 0 && check_count < 4) {
      check_count ++;
      sleep(3);
      log_trace("\ttry: %d", check_count);
    }
    if (ret > 0) {
      if (WIFEXITED(status)) {
        log_trace("excve status %d", WEXITSTATUS(status));
        return 1;
      }
    } else if (ret == -1)
      return -1;
    break;
  }

  return 0;
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
  int hostapd_running = 0;

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
    if (list_dir("/proc", kill_dir_fn, NULL) == -1) {
      log_trace("list_dir fail");
      return -1;
    }

    while((ret = run_process(hconf->hostapd_bin_path, hconf->hostapd_file_path)) > 0) {
      sleep(2);

      log_trace("Killing hostapd process");

      // Kill hostapd process if still running
      if (list_dir("/proc", kill_dir_fn, NULL) == -1) {
        log_trace("list_dir fail");
        return -1;
      }
    }

    if (ret == -1) {
      log_trace("run_process fail");
      return -1;
    }

    if (list_dir("/proc", find_dir_fn, (void *)&hostapd_running) == -1) {
      log_trace("list_dir fail");
      return -1;
    }

    if (hostapd_running)
      log_trace("hostapd running");
    else {
      log_trace("hostapd is not running");
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
  if (list_dir("/proc", kill_dir_fn, NULL) == -1) {
    log_trace("list_dir fail");
    return false;
  }

  return true;
}
