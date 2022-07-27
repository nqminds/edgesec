/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief A tool to run the capture with an input pcap file
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <libgen.h>
#include <pcap.h>

#include "utils/os.h"
#include "capture/middleware.h"
#include "capture/middlewares/header_middleware/header_middleware.h"

#define RECAP_VERSION_MAJOR 0
#define RECAP_VERSION_MINOR 0
#define RECAP_VERSION_PATCH 1

#define PCAP_READ_INTERVAL 10 // in ms

#define OPT_STRING ":p:f:mdvh"
#define USAGE_STRING "\t%s [-p filename] [-f filename] [-d] [-h] [-v]\n"
const char description_string[] = R"==(
  Run capture on an input pcap file and output to a capture db.
)==";

enum PCAP_STATE {
  PCAP_STATE_INIT = 0,
  PCAP_STATE_READ_HEADER,
  PCAP_STATE_READ_PHEADER,
  PCAP_STATE_READ_PACKET
};

struct pcap_stream_context {
  FILE *pcap_fd;
  void *data;
  enum PCAP_STATE state;
};

void show_app_version(void) {
  char buf[10];

  snprintf(buf, ARRAY_SIZE(buf), "%d.%d.%d", RECAP_VERSION_MAJOR,
           RECAP_VERSION_MINOR, RECAP_VERSION_PATCH);
  fprintf(stdout, "recap app version %s\n", buf);
}

void show_app_help(char *app_name) {
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "%s", description_string);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-p filename\t Path to the pcap file name\n");
  fprintf(stdout, "\t-f filename\t Path to the capture db\n");
  fprintf(stdout,
          "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright NQMCyber Ltd\n\n");
  exit(EXIT_SUCCESS);
}

/* Diagnose an error in command-line arguments and
   terminate the process */
void log_cmdline_error(const char *format, ...) {
  va_list argList;

  fflush(stdout); /* Flush any pending stdout */

  fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  vfprintf(stdout, format, argList);
  va_end(argList);

  fflush(stderr); /* In case stderr is not line-buffered */
  exit(EXIT_FAILURE);
}

void process_app_options(int argc, char *argv[], uint8_t *verbosity,
                         char **pcap_path, char **db_path) {
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
      case 'p':
        *pcap_path = os_strdup(optarg);
        break;
      case 'f':
        *db_path = os_strdup(optarg);
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

void eloop_tout_pcapfile_handler(void *eloop_ctx, void *user_ctx) {
  struct pcap_stream_context *pctx = (struct pcap_stream_context *)eloop_ctx;
  struct middleware_context *context = (struct middleware_context *)user_ctx;

  fprintf(stdout, "Here\n");
}

int main(int argc, char *argv[]) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *pcap_path = NULL, *db_path = NULL;
  sqlite3 *db;
  struct eloop_data *eloop;
  struct middleware_context *context = NULL;
  struct pcap_stream_context pctx = {.pcap_fd = NULL, .state = PCAP_STATE_INIT};

  process_app_options(argc, argv, &verbosity, &pcap_path, &db_path);

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  if (optind <= 1) {
    show_app_help(argv[0]);
  }

  /* Set the log level */
  log_set_level(level);

  int ret = sqlite3_open(db_path, &db);

  fprintf(stdout, "Openning db at %s\n", db_path);

  if (ret != SQLITE_OK) {
    fprintf(stdout, "Cannot open database: %s", sqlite3_errmsg(db));
    if (pcap_path != NULL) {
      os_free(pcap_path);
    }
    os_free(db_path);
    sqlite3_close(db);
    return EXIT_FAILURE;
  }

  os_free(db_path);

  fprintf(stdout, "Using %s\n", header_middleware.name);

  if ((eloop = eloop_init()) == NULL) {
    fprintf(stdout, "eloop_init fail\n");
    if (pcap_path != NULL) {
      os_free(pcap_path);
    }
    sqlite3_close(db);
    return EXIT_FAILURE;
  }

  if ((context = header_middleware.init(db, NULL, eloop, NULL)) == NULL) {
    fprintf(stdout, "init_header_middleware fail\n");
    eloop_free(eloop);
    if (pcap_path != NULL) {
      os_free(pcap_path);
    }
    sqlite3_close(db);
    return EXIT_FAILURE;
  }

  if (pcap_path != NULL) {
    if ((pctx.pcap_fd = fopen(pcap_path, "rb")) == NULL) {
      perror("fopen");
      eloop_free(eloop);
      os_free(pcap_path);
      sqlite3_close(db);
      header_middleware.free(context);
      return EXIT_FAILURE;
    }

    if (eloop_register_timeout(eloop, 0, PCAP_READ_INTERVAL,
                               eloop_tout_pcapfile_handler, (void *)&pctx,
                               (void *)&context) == -1) {
      fprintf(stdout, "eloop_register_timeout fail\n");
      eloop_free(eloop);
      os_free(pcap_path);
      sqlite3_close(db);
      header_middleware.free(context);
      fclose(pctx.pcap_fd);
      return EXIT_FAILURE;
    }
  }

  eloop_run(eloop);

  eloop_free(eloop);
  if (pcap_path != NULL) {
    os_free(pcap_path);
  }

  if (pctx.pcap_fd != NULL) {
    fclose(pctx.pcap_fd);
  }
  sqlite3_close(db);
  header_middleware.free(context);
  return EXIT_SUCCESS;
}
