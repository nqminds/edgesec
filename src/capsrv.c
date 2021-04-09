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
 * @file capsrv.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the capture service.
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
#include <pcap.h>

#include "capture/capture_config.h"
#include "capture/capture_service.h"
#include "config.h"
#include "version.h"
#include "utils/log.h"
#include "utils/os.h"
#include "utils/minIni.h"

#define OPT_STRING    ":c:i:f:t:n:p:a:o:dvhmews"
#define USAGE_STRING  "\t%s [-c config] [-d] [-h] [-v] [-i interface] " \
                      "[-f filter] [-m] [-t timeout] [-n interval] " \
                      "[-e] [-w] [-s] [-p path] [-a address] [-o port]\n"

#define DEFAULT_BUFFER_TIMEOUT 10
#define DEFAULT_PROCESS_INTERVAL 10

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
  fprintf(stdout, "capture app version %s\n",
    get_static_version_string(CAPTURE_VERSION_MAJOR,CAPTURE_VERSION_MINOR,CAPTURE_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-c config\t Path to the config file name\n");
  fprintf(stdout, "\t-i interface\t The capture interface name\n");
  fprintf(stdout, "\t-f filter\t The capture filter expression\n");
  fprintf(stdout, "\t-m\t\t Promiscuous mode\n");
  fprintf(stdout, "\t-t timeout\t The buffer timeout (milliseconds)\n");
  fprintf(stdout, "\t-n interval\t The process intereval (milliseconds)\n");
  fprintf(stdout, "\t-e\t\t Immediate mode\n");
  fprintf(stdout, "\t-w\t\t Write to db\n");
  fprintf(stdout, "\t-s\t\t Sync the db\n");
  fprintf(stdout, "\t-p path\t\t The db path\n");
  fprintf(stdout, "\t-a address\t The db sync address\n");
  fprintf(stdout, "\t-o port\t\t The db sync port\n");
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

long get_arg_num(char *port_str)
{
  if (!is_number(port_str))
    return -1;
  
  return strtol(port_str, NULL, 10);
}

void process_app_options(int argc, char *argv[], uint8_t *verbosity,
                          const char **filename, struct capture_conf *config)
{
  int opt;

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
    case 'c':
      *filename = optarg;
      break;
    case 'i':
      strncpy(config->capture_interface, optarg, IFNAMSIZ);
      break;
    case 'f':
      config->filter = os_malloc(strlen(optarg) + 1);
      strncpy(config->filter, optarg, IFNAMSIZ);
      break;
    case 'm':
      config->promiscuous = true;
      break;
    case 't':
      config->buffer_timeout = get_arg_num(optarg);
      if (config->buffer_timeout < 0) {
        log_cmdline_error("Wrong buffer timeout\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'n':
      config->process_interval = get_arg_num(optarg);
      if (config->process_interval < 0) {
        log_cmdline_error("Wrong process interval\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'e':
      config->immediate = true;
      break;
    case 'w':
      config->db_write = true;
      break;
    case 's':
      config->db_sync = true;
      break;
    case 'p':
      strncpy(config->db_path, optarg, MAX_OS_PATH_LEN);
      break;
    case 'a':
      strncpy(config->db_sync_address, optarg, MAX_WEB_PATH_LEN);
      break;
    case 'o':
      config->db_sync_port = get_arg_num(optarg);
      if (config->db_sync_port <= 0 || config->db_sync_port > 65535) {
        log_cmdline_error("Unrecognized port value\n");
        exit(EXIT_FAILURE);
      }
      break;
    case ':':
      log_cmdline_error("Missing argument for -%c\n", optopt);
      exit(EXIT_FAILURE);
      break;
    case '?':
      log_cmdline_error("Unrecognized option -%c\n", optopt);
      exit(EXIT_FAILURE);
      break;
    default: show_app_help(argv[0]);
    }
  }
}

int main(int argc, char *argv[])
{
  uint8_t verbosity = 0;
  uint8_t level = 0;
  const char *filename = NULL;
  struct capture_conf config;

  // Init the capture config struct
  memset(&config, 0, sizeof(struct capture_conf));
  config.buffer_timeout = DEFAULT_BUFFER_TIMEOUT;
  config.process_interval = DEFAULT_PROCESS_INTERVAL;
  process_app_options(argc, argv, &verbosity, &filename, &config);

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
  if (filename != NULL) {
    load_capture_config(filename, &config);
  }

  if (run_capture(&config) == -1) {
    fprintf(stderr, "run_capture fail\n");
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}