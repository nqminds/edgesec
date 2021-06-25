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
 * @file supervisor.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the supervisor service.
 */

#include <stdbool.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "sqlite_fingerprint_writer.h"

#include "utils/log.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/utarray.h"
#include "utils/domain.h"

#include "cmd_processor.h"

#define FINGERPRINT_DB_NAME "fingerprint" SQLITE_EXTENSION

void eloop_read_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  char **ptr = NULL;
  UT_array *cmd_arr;
  process_cmd_fn cfn;
  char buf[MAX_DOMAIN_RECEIVE_DATA];
  struct supervisor_context *context = (struct supervisor_context *) sock_ctx;

  utarray_new(cmd_arr, &ut_str_icd);

  char *client_addr = os_malloc(sizeof(struct sockaddr_un));
  ssize_t num_bytes = read_domain_data(sock, buf, MAX_DOMAIN_RECEIVE_DATA, client_addr, 0);
  if (num_bytes == -1) {
    log_trace("read_domain_data fail");
    goto end;  
  }

  log_trace("Supervisor received %ld bytes from %s", (long) num_bytes, client_addr);
  if (process_domain_buffer(buf, num_bytes, cmd_arr, context->domain_delim) == false) {
    log_trace("process_domain_buffer fail");
    goto end;
  }

  ptr = (char**) utarray_next(cmd_arr, ptr);

  if ((cfn = get_command_function(*ptr)) != NULL) {
    if (cfn(sock, client_addr, context, cmd_arr) == -1) {
      log_trace("%s fail", *ptr);
      goto end;
    }
  }

end:
  os_free(client_addr);
  utarray_free(cmd_arr);
}

bool close_supervisor(int sock)
{
  if (sock != -1) {
    if (close(sock) == -1) {
      log_err("close");
      return false;
    }
  }

  return true;
}

int run_supervisor(char *server_path, struct supervisor_context *context)
{
  int sock;
  char *db_path = NULL;

  db_path = construct_path(context->db_path, FINGERPRINT_DB_NAME);
  if (db_path == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  if (open_sqlite_fingerprint_db(db_path, &context->fingeprint_db) < 0) {
    log_trace("open_sqlite_fingerprint_db fail");
    os_free(db_path);
    return -1;
  }

  os_free(db_path);

  if ((sock = create_domain_server(server_path)) == -1) {
    log_trace("create_domain_server fail");
    return -1;
  }

  if (eloop_register_read_sock(sock, eloop_read_sock_handler, NULL, (void *)context) ==  -1) {
    log_trace("eloop_register_read_sock fail");
    close_supervisor(sock);
    return -1;
  }

  return sock;
}
