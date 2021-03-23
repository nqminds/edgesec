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
 * @file restsrv.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the rest server app.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <inttypes.h>
#include <sys/un.h>
#include <sys/socket.h>


#include "supervisor/cmd_processor.h"
#include "microhttpd.h"
#include "version.h"
#include "utils/os.h"
#include "utils/log.h"
#include "utils/minIni.h"

#define OPT_STRING    ":a:s:p:dvh"
#define USAGE_STRING  "\t%s [-s address] [-a address] [-p port] [-d] [-h] [-v]\n"

#define JSON_RESPONSE_OK "{\"cmd\":\"%s\",\"response\":\"%s\"}"
#define JSON_RESPONSE_FAIL "{\"error\":\"invalid get request\"}"
char *socket_path = "\0hidden";

static __thread char version_buf[10];

struct domain_options {
  int supervisor_sock;
  int ap_sock;
};

char *get_static_version_string(uint8_t major, uint8_t minor, uint8_t patch)
{
  int ret = snprintf(version_buf, 10, "%d.%d.%d", major, minor, patch);

  if (ret < 0) {
    fprintf(stderr, "snprintf");
    return NULL;
  }

  return version_buf;
}

void show_app_version(void)
{
  fprintf(stdout, "restsrv app version %s\n",
    get_static_version_string(RESTSRV_VERSION_MAJOR, RESTSRV_VERSION_MINOR,
                              RESTSRV_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-s address\t Path to supervisor socket\n");
  fprintf(stdout, "\t-a address\t Path to AP socket\n");
  fprintf(stdout, "\t-p port\t\t Server port\n");
  fprintf(stdout, "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright Nquirignminds Ltd\n\n");
  exit(EXIT_SUCCESS);
}

/* Diagnose an error in command-line arguments and terminate the process */
void log_cmdline_error(const char *format, ...)
{
    va_list argList;

    fflush(stdout);           /* Flush any pending stdout */

    fprintf(stdout, "Command-line usage error: ");
    va_start(argList, format);
    vfprintf(stdout, format, argList);
    va_end(argList);

    fflush(stderr);           /* In case stderr is not line-buffered */
    exit(EXIT_FAILURE);
}

int get_port(char *port_str)
{
  if (!is_number(port_str))
    return -1;
  
  return strtol(port_str, NULL, 10);
}

void process_app_options(int argc, char *argv[], char *spath, char *apath,
  int *port, uint8_t *verbosity)
{
  int opt;
  int p;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
    case 'd':
      (*verbosity)++;
      break;
    case 'h':
      show_app_help(argv[0]);
      break;
    case 'v':
      show_app_version();
      break;
    case 's':
      memcpy(spath, optarg, strlen(optarg) + 1);
      break;
    case 'a':
      memcpy(apath, optarg, strlen(optarg) + 1);
      break;
    case 'p':
      if ((p = get_port(optarg)) < 0) {
        log_cmdline_error("Unrecognized port value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      *port = p;
      break;
    case ':':
      log_cmdline_error("Missing argument for -%c\n", optopt);
      exit(EXIT_FAILURE);
    case '?':
      log_cmdline_error("Unrecognized option -%c\n", optopt);
      exit(EXIT_FAILURE);
    default: show_app_help(argv[0]);
    }
  }
}

int create_domain_client(void)
{
  struct sockaddr_un claddr;
  int sock;
  memset(&claddr, 0, sizeof(struct sockaddr_un));
  claddr.sun_family = AF_UNIX;
  *claddr.sun_path = '\0';
  strncpy(claddr.sun_path+1, socket_path+1, sizeof(claddr.sun_path)-2);

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    log_err("socket");
    return -1;
  }

  if (connect(sock, (struct sockaddr *) &claddr, sizeof(struct sockaddr_un)) == -1) {
    log_err("connect");
    return -1;
  }

  return sock;
}

int print_out_key (void *cls, enum MHD_ValueKind kind, 
                   const char *key, const char *value)
{
  log_info("HEADER --> key=%s value=%s", key, value);
  return MHD_YES;
}

char* create_command_string(char *cmd, char *args, char *cmd_str)
{
  char *cmd_tmp;
  if (cmd == NULL || cmd_str == NULL)
    return NULL;

  if (strlen(cmd)) {
    cmd_tmp = allocate_string(cmd);
    upper_string(cmd_tmp);
    if (args ==  NULL)
      sprintf(cmd_str, "%s\n", cmd_tmp);
    else
      sprintf(cmd_str, "%s %s\n", cmd_tmp, args);
    replace_string_char(cmd_str, ',', CMD_DELIMITER);
    os_free(cmd_tmp);

    return cmd_str;
  }

  return NULL;
}

enum MHD_Result create_connection_response(char *data, struct MHD_Connection *connection)
{
  struct MHD_Response *response;
  enum MHD_Result ret;
  response = MHD_create_response_from_buffer(strlen(data), data, MHD_RESPMEM_MUST_COPY);
  if (response == NULL) {
    log_debug("NULL response error");
    // os_free(me);
    return MHD_NO;
  }

  ret = MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
  if (ret == MHD_NO) {
    log_debug("MHD_add_response_header error");
    MHD_destroy_response(response);  
    // os_free(me);
    return MHD_NO;
  }
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

static enum MHD_Result mhd_reply(void *cls, struct MHD_Connection *connection, const char *url,
  const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
  static int aptr, response_size = 0;
  char *fmt = cls, *cmd, *args;
  char cmd_str[255];
  char response_buf[255];
  enum MHD_Result ret;

  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  /* unexpected method */
  if (0 != strcmp (method, "GET")) {
    return MHD_NO;
  }

  if (&aptr != *ptr) {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }

  *ptr = NULL;                  /* reset when done */
  MHD_get_connection_values(connection, MHD_HEADER_KIND, (MHD_KeyValueIterator)&print_out_key, NULL);
  cmd = (char *) MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cmd");
  args = (char *) MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "args");

  log_info("URL --> %s %s", method, url);
  log_info("PARAMS --> cmd=%s args=%s", cmd, args);

  if (create_command_string(cmd, args, cmd_str) == NULL) {
    log_debug("create_command_string fail");
    sprintf(response_buf, JSON_RESPONSE_FAIL);
    return create_connection_response(response_buf, connection);
  }

  // // Here send the command to the UNIX domain socket

  sprintf(response_buf, JSON_RESPONSE_OK, cmd, "12345");
  return create_connection_response(response_buf, connection);
}

int main(int argc, char *argv[])
{
  struct MHD_Daemon *d;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char apath[MAX_OS_PATH_LEN], spath[MAX_OS_PATH_LEN];
  int port = -1;
  struct domain_options dopt;

  process_app_options(argc, argv, apath, spath, &port, &verbosity); 

  if (optind <= 1) show_app_help(argv[0]);

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  // Set the log level
  log_set_level(level);

  if (port == -1) {
    log_cmdline_error("Unrecognized port value -%d\n", port);
    exit(EXIT_FAILURE); 
  }

  fprintf(stdout, "Starting server with:\n");
  fprintf(stdout, "Supervisor address --> %s\n", apath);
  fprintf(stdout, "AP address --> %s\n", spath);
  fprintf(stdout, "Port --> %d\n", port);

  if ((dopt.supervisor_sock = create_domain_client()) == -1) {
    fprintf(stderr,"create_domain_client fail");
    exit(EXIT_FAILURE);
  }

  if ((dopt.ap_sock = create_domain_client()) == -1) {
    close(dopt.supervisor_sock);
    fprintf(stderr,"create_domain_client fail");
    exit(EXIT_FAILURE);
  }

  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION, (uint16_t) port,
                        NULL, NULL, &mhd_reply, NULL, MHD_OPTION_END);

  if (d == NULL) {
    fprintf(stderr, "Error: Failed to start server\n");
    exit(EXIT_FAILURE);
  }

  (void) getc (stdin);
  MHD_stop_daemon (d);
  close(dopt.supervisor_sock);
  close(dopt.ap_sock);
  fprintf(stdout, "Server stopped\n");
  exit(EXIT_SUCCESS);
}