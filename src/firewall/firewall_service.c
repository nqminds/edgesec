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
 * @file firewall_service.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the firewall service commands.
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

int fw_set_ip_forward(void)
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