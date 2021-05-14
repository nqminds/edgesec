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
 * @file radius_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the radius service.
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

#include "radius_server.h"

struct radius_server_data *run_radius(struct radius_conf *rconf,
  void *radius_callback_fn, void *radius_callback_args)
{
  struct radius_client *client = init_radius_client(rconf, radius_callback_fn, radius_callback_args);

  return radius_server_init(rconf->radius_port, client);
}

void close_radius(struct radius_server_data *srv)
{
  if (srv != NULL) {
    radius_server_deinit(srv);
  }
}
