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
 * @file edgesec.c 
 * @author Alexandru Mereacre 
 * @brief File containing the edgesec tool implementations.
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

#include "version.h"
#include "utils/log.h"
#include "utils/os.h"
#include "utils/minIni.h"
#include "utils/utarray.h"
#include "utils/if.h"
#include "dhcp/dhcp_config.h"
#include "engine.h"
#include "if_service.h"
#include "config.h"

#define OPT_STRING    ":c:dvh"
#define USAGE_STRING  "\t%s [-c filename] [-d] [-h] [-v]\n"

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};
static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};
static const UT_icd config_dhcpinfo_icd = {sizeof(config_dhcpinfo_t), NULL, NULL, NULL};

static __thread char version_buf[10];

static void lock_fn(bool lock)
{
  int res;

  if (lock) {
    res = pthread_mutex_lock(&mtx);
    if (res != 0) {
      log_err_exp("pthread_mutex_lock\n");
    }
  } else {
    res = pthread_mutex_unlock(&mtx);
    if (res != 0) {
      log_err_exp("pthread_mutex_unlock\n");
    }
  }
}

char *get_static_version_string(uint8_t major, uint8_t minor, uint8_t patch)
{
  int ret = snprintf(version_buf, 10, "%d.%d.%d", major, minor, patch);

  if (ret < 0) {
    log_trace("snprintf");
    return NULL;
  }

  return version_buf;
}

void show_app_version(void)
{
  fprintf(stdout, "edgesec app version %s\n",
    get_static_version_string(EDGESEC_VERSION_MAJOR, EDGESEC_VERSION_MINOR,
                              EDGESEC_VERSION_PATCH));
}
void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, app_name);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-c filename\t Path to the config file name\n");
  fprintf(stdout, "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright Nquirignminds Ltd\n\n");
  exit(EXIT_SUCCESS);
}

/* Diagnose an error in command-line arguments and
   terminate the process */
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

void process_app_options(int argc, char *argv[], uint8_t *verbosity,
                          const char **config_filename)
{
  int opt;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
    case 'h':
      show_app_help(argv[0]);
      break;
    case 'v':
      show_app_version();
      break;
    case 'c':
      *config_filename = optarg;
      break;
    case 'd':
      (*verbosity)++;
      break;
    case ':':
      log_cmdline_error("Missing argument for -%c\n", optopt);
      break;
    case '?':
      log_cmdline_error("Unrecognized option -%c\n", optopt);
      break;
    default: show_app_help(argv[0]);
    }
  }
}

char *get_app_name(char *app_path) {
  return basename(app_path);
}

int main(int argc, char *argv[])
{
  uint8_t verbosity = 0;
  uint8_t level = 0;
  const char *filename = NULL;
  UT_array *bin_path_arr;
  UT_array *config_ifinfo_arr;
  UT_array *config_dhcpinfo_arr;
  UT_array *mac_conn_arr;
  UT_array *server_arr;
  struct app_config config;
  
  // Init the app config struct
  memset(&config, 0, sizeof(struct app_config));

  // Create the empty dynamic array for bin path strings
  utarray_new(bin_path_arr, &ut_str_icd);
  config.bin_path_array = bin_path_arr;

  // Create the config interface
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);
  config.config_ifinfo_array = config_ifinfo_arr;

  // Create the dhcp config interface
  utarray_new(config_dhcpinfo_arr, &config_dhcpinfo_icd);
  config.dhcp_config.config_dhcpinfo_array = config_dhcpinfo_arr;

  // Create the connections list
  utarray_new(mac_conn_arr, &mac_conn_icd);
  config.connections = mac_conn_arr;

  // Create the dns server array
  utarray_new(server_arr, &ut_str_icd);
  config.dns_config.server_array = server_arr;

  process_app_options(argc, argv, &verbosity, &filename);

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }
  
  if (optind <= 1) show_app_help(argv[0]);

  load_app_config(filename, &config);

  // Kill all edgesec processes if running
  if (config.kill_running_proc) {
    if(!kill_process(get_app_name(argv[0]))){
      fprintf(stderr, "kill_process fail.\n");
      exit(1);
    }
  }

  if (!run_engine(&config, level)) {
    fprintf(stderr, "Failed to start edgesec engine.\n");
  } else
    fprintf(stderr, "Edgesec engine stopped.\n");

  utarray_free(bin_path_arr);
  utarray_free(config_ifinfo_arr);
  utarray_free(config_dhcpinfo_arr);
  utarray_free(mac_conn_arr);
  utarray_free(server_arr);
  exit(0);
}