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
 * @file system_checks.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the systems commands checks.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>


#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"

#define IP_FORWARD_PATH "/proc/sys/net/ipv4/ip_forward"

hmap_str_keychar *check_systems_commands(char *commands[], UT_array *bin_path_arr, hmap_str_keychar *hmap_bin_hashes)
{
  (void) hmap_bin_hashes;

  if (commands == NULL) {
    log_debug("commands param NULL");
    return NULL;
  }

  hmap_str_keychar *hmap_bin_paths = hmap_str_keychar_new();
  
  for(uint8_t idx = 0; commands[idx] != NULL; idx ++) {
    log_debug("Checking %s command...", commands[idx]);
    char *path = get_secure_path(bin_path_arr, commands[idx], false);
    if (path == NULL) {
      log_debug("%s command not found", commands[idx]);
      free(path);
      return NULL;
    } else {
      log_debug("%s command found at %s", commands[idx], path);
      if(!hmap_str_keychar_put(&hmap_bin_paths, commands[idx], path)) {
        log_debug("hmap_str_keychar_put error");
        free(path);
        hmap_str_keychar_free(&hmap_bin_paths);
        return NULL;
      }
    }

    free(path);
  }

  return hmap_bin_paths;
}

int set_ip_forward(void)
{
  char buf[2];
  int fd = open(IP_FORWARD_PATH, O_RDWR);
  if (read(fd, buf, 1) < 0) {
    log_err("read");
    close(fd);
    return -1;
  }

  log_trace("Current IP forward flag %c", buf[0]);

  if (buf[0] == 0x30) {
    log_trace("Setting IP forward flag to 1");
    if (lseek(fd, 0 , SEEK_SET) < 0) {
      log_err("lseek")  ;
      close(fd);
      return -1;
    }

    buf[0] = 0x31;

	  if (write(fd, buf, 1) < 0) {
      log_err("write");
        close(fd);
        return -1;
    }
  }
  close(fd);
  return 0; 
}