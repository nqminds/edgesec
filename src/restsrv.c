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


#include "microhttpd.h"
#include "version.h"
#include "utils/os.h"
#include "utils/minIni.h"

#define OPT_STRING    ":a:s:p:vh"
#define USAGE_STRING  "\t%s [-s address] [-a address] [-p port] [-h] [-v]\n"

#define PAGE \
  "<html><head><title>libmicrohttpd demo</title></head><body>Query string for &quot;%s&quot; was &quot;%s&quot;</body></html>"

static __thread char version_buf[10];

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

void process_app_options(int argc, char *argv[], char *spath, char *apath, int *port)
{
  int opt;
  int p;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
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

static enum MHD_Result
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr)
{
  static int aptr;
  const char *fmt = cls;
  const char *val;
  char *me;
  struct MHD_Response *response;
  enum MHD_Result ret;

  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, "GET"))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
  {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }

  *ptr = NULL;                  /* reset when done */
  val = MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "q");
  me = os_malloc (snprintf (NULL, 0, fmt, "q", val) + 1);

  if (me == NULL)
    return MHD_NO;

  fprintf(stdout, "URL --> %s %s\n", method, url);

  sprintf (me, fmt, "q", val);
  response = MHD_create_response_from_buffer (strlen (me), me,
                                              MHD_RESPMEM_MUST_FREE);
  if (response == NULL)
  {
    os_free (me);
    return MHD_NO;
  }
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}

int main(int argc, char *argv[])
{
  struct MHD_Daemon *d;

  char apath[MAX_OS_PATH_LEN], spath[MAX_OS_PATH_LEN];
  int port = -1;

  process_app_options(argc, argv, apath, spath, &port); 

  if (optind <= 1) show_app_help(argv[0]);

  if (port == -1) {
    log_cmdline_error("Unrecognized port value -%d\n", port);
    exit(EXIT_FAILURE); 
  }

  fprintf(stdout, "Starting server with:\n");
  fprintf(stdout, "Supervisor address --> %s\n", apath);
  fprintf(stdout, "AP address --> %s\n", spath);
  fprintf(stdout, "Port --> %d\n", port);

  d = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_EPOLL | MHD_USE_ERROR_LOG,
                        (uint16_t) port,
                        NULL, NULL, &ahc_echo, PAGE, MHD_OPTION_END);

  if (d == NULL) {
    fprintf(stderr, "Error: Failed to start server\n");
    exit(EXIT_FAILURE);
  }

  (void) getc (stdin);
  MHD_stop_daemon (d);
  fprintf(stdout, "Server stopped\n");
  exit(EXIT_SUCCESS);
}