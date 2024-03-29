/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the edgesec tool implementations.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <eloop.h>
#include "config.h"
#include "dhcp/dhcp_config.h"
#include "runctl.h"
#include "utils/allocs.h"
#include "utils/iface.h"
#include "utils/log.h"
#include "utils/os.h"
#include "version.h"

#define OPT_STRING ":c:f:mdvh"
#define USAGE_STRING "\t%s [-c filename] [-f filename] [-m] [-d] [-h] [-v]\n"
const char description_string[] =
    "NquiringMinds EDGESec Network Security Router.\n"
    "\n"
    "Creates a secure and paritioned Wifi access point, using vlans\n"
    "and can analyse network traffic.\n"

    "Contains multiple services controlled by the tool engine:\n"
    "  1. Supervisor: registers network joining and DHCP requests.\n"
    "     Exposes a command interface via a UNIX domain socket.\n"
    "  2. WiFi Access Point: Manages WiFi AP.\n"
    "  3. Subnet: Creates subnets, virtual LANs, and IP ranges.\n"
    "  4. DHCP: Assigns IP addresses to connected devices.\n"
    "  5. RADIUS: Access control for the WiFi AP using\n"
    "     credentials/MAC address.\n"
    "  6. State machine: Networking monitoring and management.\n";

static pthread_mutex_t log_lock;

static void log_lock_fun(bool lock) {
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

static void show_app_version(void) {
  fprintf(stdout, "edgesec app version %s\n", EDGESEC_VERSION);
}

static void show_app_help(char *app_name) {
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "%s", description_string);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-c filename\t Path to the config file name\n");
  fprintf(stdout, "\t-f filename\t Log file name\n");
  fprintf(stdout, "\t-m\t\t Run as daemon\n");
  fprintf(stdout,
          "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright NQMCyber Ltd\n\n");
  exit(EXIT_SUCCESS);
}

/* Diagnose an error in command-line arguments and
   terminate the process */
PRINTF_FORMAT(1, 2) static void log_cmdline_error(const char *format, ...) {
  va_list argList;

  fflush(stdout); /* Flush any pending stdout */

  fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  vfprintf(stdout, format, argList);
  va_end(argList);

  fflush(stderr); /* In case stderr is not line-buffered */
  exit(EXIT_FAILURE);
}

static void process_app_options(int argc, char *argv[], uint8_t *verbosity,
                                bool *daemon, char **config_filename,
                                char **log_filename) {
  int opt;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
      case 'h':
        show_app_help(argv[0]);
        break;
      case 'v':
        show_app_version();
        exit(EXIT_SUCCESS);
        break;
      case 'c':
        *config_filename = os_strdup(optarg);
        break;
      case 'f':
        *log_filename = os_strdup(optarg);
        break;
      case 'm':
        *daemon = true;
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
      default:
        show_app_help(argv[0]);
    }
  }
}

int main(int argc, char *argv[]) {
  bool daemon = false;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *config_filename = NULL, *log_filename = NULL;
  struct app_config config;

  // Init the app config struct
  memset(&config, 0, sizeof(struct app_config));

  process_app_options(argc, argv, &verbosity, &daemon, &config_filename,
                      &log_filename);

#ifdef WITH_CRYPTO_SERVICE
  char *env_key_value;
  if ((env_key_value = getenv("CRYPT_KEY")) != NULL) {
    os_strlcpy(config.crypt_secret, env_key_value, MAX_USER_SECRET);
  }
#endif

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  if (optind <= 1)
    show_app_help(argv[0]);

  if (daemon && become_daemon(0) == -1) {
    fprintf(stderr, "become_daemon fail");
    return EXIT_FAILURE;
  }

  if (pthread_mutex_init(&log_lock, NULL) != 0) {
    fprintf(stderr, "mutex init has failed\n");
    return EXIT_FAILURE;
  }

  log_set_lock(log_lock_fun);

  /* Set the log level */
  log_set_level(level);

  if (log_filename != NULL) {
    if (log_open_file(log_filename) < 0) {
      fprintf(stderr, "log_open_file fail");
      return EXIT_FAILURE;
    }
  }

  if (load_app_config(config_filename, &config) < 0) {
    fprintf(stderr, "load_app_config fail\n");
    return EXIT_FAILURE;
  }

  if (create_pid_file(config.pid_file_path, FD_CLOEXEC) < 0) {
    fprintf(stderr, "create_pid_file fail");
    return EXIT_FAILURE;
  }

  os_init_random_seed();

  if (run_ctl(&config, NULL) < 0) {
    fprintf(stderr, "Failed to start edgesec engine.\n");
    return EXIT_FAILURE;
  } else
    fprintf(stderr, "Edgesec engine stopped.\n");

  free_app_config(&config);

  if (config_filename != NULL)
    os_free(config_filename);
  if (log_filename != NULL)
    os_free(log_filename);

  pthread_mutex_destroy(&log_lock);
  return EXIT_SUCCESS;
}
