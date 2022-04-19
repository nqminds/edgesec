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
#include <linux/if.h>
#include <libgen.h>
#include <pcap.h>

#include "capture/capture_config.h"
#include "capture/capture_service.h"
#include "config.h"
#include "version.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/minIni.h"

static __thread char version_buf[10];

pthread_mutex_t log_lock;

void log_lock_fun(bool lock) {
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

char *get_static_version_string(uint8_t major, uint8_t minor, uint8_t patch) {
  int ret = snprintf(version_buf, 10, "%d.%d.%d", major, minor, patch);

  if (ret < 0) {
    fprintf(stderr, "snprintf");
    return NULL;
  }

  return version_buf;
}

int show_app_version(void) {
  fprintf(stdout, "capture app version %s\n",
          get_static_version_string(CAPTURE_VERSION_MAJOR,
                                    CAPTURE_VERSION_MINOR,
                                    CAPTURE_VERSION_PATCH));
  return 1;
}

int show_app_help(char *app_name) {
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, CAPTURE_USAGE_STRING, basename(app_name));
  fprintf(stdout, "\n%s", capture_description_string);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "%s", CAPTURE_OPT_DEFS);
  fprintf(stdout, "Copyright NQMCyber Ltd\n");
  return 1;
}

/* Diagnose an error in command-line arguments and terminate the process */
int log_cmdline_error(const char *format, ...) {
  va_list argList;

  fflush(stdout); /* Flush any pending stdout */

  fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  vfprintf(stdout, format, argList);
  va_end(argList);

  fflush(stderr); /* In case stderr is not line-buffered */
  return -1;
}

int process_app_options(int argc, char *argv[], uint8_t *verbosity,
                        const char **filename, struct capture_conf *config) {
  int opt, ret;

  while ((opt = getopt(argc, argv, CAPTURE_OPT_STRING)) != -1) {
    switch (opt) {
      case 'd':
        (*verbosity)++;
        break;
      case 'h':
        return show_app_help(argv[0]);
      case 'v':
        return show_app_version();
      case 'c':
        *filename = optarg;
        break;
      case ':':
        return log_cmdline_error("Missing argument for -%c\n", optopt);
      case '?':
        return log_cmdline_error("Unrecognized option -%c\n", optopt);
      default:
        ret = capture_opt2config(opt, optarg, config);
        if (ret < 0) {
          return log_cmdline_error("Wrong argument value for -%c\n", optopt);
        } else if (ret > 0) {
          return show_app_help(argv[0]);
        }
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int ret;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  const char *filename = NULL;
  struct capture_conf config;

  // Init the capture config struct
  memset(&config, 0, sizeof(struct capture_conf));
  config.buffer_timeout = DEFAULT_CAPTURE_TIMEOUT;
  config.process_interval = DEFAULT_CAPTURE_INTERVAL;
  config.sync_store_size = -1;
  config.sync_send_size = -1;

  ret = process_app_options(argc, argv, &verbosity, &filename, &config);

  if (ret < 0) {
    fprintf(stderr, "process_app_options fail");
    return EXIT_FAILURE;
  } else if (ret > 0) {
    return EXIT_SUCCESS;
  }

  if (optind <= 1) {
    show_app_help(argv[0]);
    return EXIT_SUCCESS;
  }

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  if (pthread_mutex_init(&log_lock, NULL) != 0) {
    fprintf(stderr, "mutex init has failed\n");
    return EXIT_FAILURE;
  }

  log_set_lock(log_lock_fun);

  // Set the log level
  log_set_level(level);
  if (filename != NULL) {
    load_capture_config(filename, &config);
  }

  if (run_capture(&config) < 0) {
    fprintf(stderr, "run_capture fail\n");
    pthread_mutex_destroy(&log_lock);
    return EXIT_FAILURE;
  }

  pthread_mutex_destroy(&log_lock);
  return EXIT_SUCCESS;
}
