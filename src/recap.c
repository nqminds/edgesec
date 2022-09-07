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
#include "capture/middlewares/header_middleware/packet_queue.h"

#define RECAP_VERSION_MAJOR 0
#define RECAP_VERSION_MINOR 0
#define RECAP_VERSION_PATCH 1

#define PCAP_READ_INTERVAL 10 // in ms
#define PCAP_READ_SIZE 1024   // bytes

#define OPT_STRING ":p:f:mdvh"
#define USAGE_STRING "\t%s [-p filename] [-f filename] [-d] [-h] [-v]\n"
const char description_string[] = R"==(
  Run capture on an input pcap file and output to a capture db.
)==";

enum PCAP_STATE {
  PCAP_STATE_INIT = 0,
  PCAP_STATE_READ_PCAP_HEADER,
  PCAP_STATE_READ_PKT_HEADER,
  PCAP_STATE_READ_PACKET,
  PCAP_STATE_FIN
};

struct pcap_pkthdr32 {
  uint32_t ts_sec;  /* timestamp seconds.*/
  uint32_t ts_usec; /* timestamp microseconds.*/
  uint32_t caplen;  /* length of portion present */
  uint32_t len;     /* length this packet (off wire) */
} STRUCT_PACKED;

struct pcap_stream_context {
  FILE *pcap_fd;
  char *pcap_data;
  ssize_t data_size;
  ssize_t total_size;
  enum PCAP_STATE state;
  bool exit_error;
  struct pcap_file_header pcap_header;
  struct pcap_pkthdr32 pkt_header;
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

ssize_t read_pcap_stream_fd(struct pcap_stream_context *pctx, size_t len,
                            char **data) {
  if ((*data = os_malloc(len)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)fread(*data, sizeof(char), len, pctx->pcap_fd);
}

ssize_t read_pcap(struct pcap_stream_context *pctx, size_t len) {
  char *data = NULL;
  ssize_t read_size, current_size;

  if ((read_size = read_pcap_stream_fd(pctx, len, &data)) < 0) {
    log_error("read_pcap_stream_fd fail");
    return -1;
  }
  pctx->total_size += read_size;

  current_size = read_size + pctx->data_size;

  if (read_size > 0) {
    if ((pctx->pcap_data = os_realloc(pctx->pcap_data, current_size)) == NULL) {
      log_errno("os_realloc");
      os_free(data);
      return -1;
    }
    os_memcpy(&pctx->pcap_data[pctx->data_size], data, read_size);
    pctx->data_size = current_size;
  }
  os_free(data);

  return read_size;
}

int process_pcap_header_state(struct pcap_stream_context *pctx) {
  ssize_t read_size = 0;
  ssize_t pcap_header_size = (ssize_t)sizeof(struct pcap_file_header);

  size_t len = (pcap_header_size > pctx->data_size)
                   ? pcap_header_size - pctx->data_size
                   : 0;

  if ((read_size = read_pcap(pctx, len)) < 0) {
    log_error("read_pcap fail");
    return -1;
  }

  if (pctx->data_size >= pcap_header_size) {
    log_trace("Received pcap header:");
    os_memcpy(&pctx->pcap_header, pctx->pcap_data, pcap_header_size);
    log_trace("\tpcap_file_header version_major = %d",
              pctx->pcap_header.version_major);
    log_trace("\tpcap_file_header version_minor = %d",
              pctx->pcap_header.version_minor);
    log_trace("\tpcap_file_header snaplen = %d", pctx->pcap_header.snaplen);
    log_trace("\tpcap_file_header linktype = %d", pctx->pcap_header.linktype);
    pctx->data_size = 0;
    pctx->state = PCAP_STATE_READ_PKT_HEADER;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_STATE_FIN;
  }

  return 0;
}

int process_pkt_header_state(struct pcap_stream_context *pctx) {
  ssize_t read_size = 0;
  ssize_t pkt_header_size = (ssize_t)sizeof(struct pcap_pkthdr32);

  size_t len = (pkt_header_size > pctx->data_size)
                   ? pkt_header_size - pctx->data_size
                   : 0;

  if ((read_size = read_pcap(pctx, len)) < 0) {
    log_error("read_pcap fail");
    return -1;
  }

  if (pctx->data_size >= pkt_header_size) {
    log_trace("Received pkt header:");
    os_memcpy(&pctx->pkt_header, pctx->pcap_data, pkt_header_size);
    log_trace("\tpcap_pkthdr ts_sec = %llu", pctx->pkt_header.ts_sec);
    log_trace("\tpcap_pkthdr ts_usec = %llu", pctx->pkt_header.ts_usec);
    log_trace("\tpcap_pkthdr caplen = %llu", pctx->pkt_header.caplen);
    log_trace("\tpcap_pkthdr len = %llu", pctx->pkt_header.len);

    if (pctx->pkt_header.caplen > pctx->pkt_header.len) {
      log_error("caplen > len");
      return -1;
    }

    pctx->data_size = 0;
    pctx->state = PCAP_STATE_READ_PACKET;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_STATE_FIN;
  }

  return 0;
}

int process_pkt_read_state(struct pcap_stream_context *pctx,
                           struct middleware_context *mctx) {
  ssize_t read_size = 0;
  size_t len = (pctx->pkt_header.caplen > pctx->data_size)
                   ? pctx->pkt_header.caplen - pctx->data_size
                   : 0;

  if ((read_size = read_pcap(pctx, len)) < 0) {
    log_error("read_pcap fail");
    return -1;
  }

  if (pctx->data_size >= pctx->pkt_header.caplen) {
    log_trace("Received pkt data");

    struct pcap_pkthdr header;
    header.ts.tv_sec = pctx->pkt_header.ts_sec;
    header.ts.tv_usec = pctx->pkt_header.ts_usec;
    header.caplen = pctx->pkt_header.caplen;
    header.len = pctx->pkt_header.len;

    if (header_middleware.process(
            mctx, pcap_datalink_val_to_name(pctx->pcap_header.linktype),
            &header, (uint8_t *)pctx->pcap_data, "pcap") < 0) {
      log_error("process_header_middleware fail");
      return -1;
    }

    pctx->data_size = 0;
    pctx->state = PCAP_STATE_READ_PKT_HEADER;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_STATE_FIN;
  }

  return 0;
}

int process_pcap_stream_state(struct pcap_stream_context *pctx,
                              struct middleware_context *mctx) {
  log_trace("Processing pcap file stream %zu bytes", pctx->total_size);

  switch (pctx->state) {
    case PCAP_STATE_INIT:
      if ((pctx->pcap_data = os_malloc(sizeof(char))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      pctx->total_size = 0;
      pctx->data_size = 0;
      pctx->state = PCAP_STATE_READ_PCAP_HEADER;
      return 1;
    case PCAP_STATE_READ_PCAP_HEADER:
      if (process_pcap_header_state(pctx) < 0) {
        log_error("process_pcap_header_state fail");
        return -1;
      }
      return 1;
    case PCAP_STATE_READ_PKT_HEADER:
      if (process_pkt_header_state(pctx) < 0) {
        log_error("process_pkt_header_state fail");
        return -1;
      }
      return 1;
    case PCAP_STATE_READ_PACKET:
      if (process_pkt_read_state(pctx, mctx) < 0) {
        log_error("process_pkt_read_state fail");
        return -1;
      }
      return 1;
    case PCAP_STATE_FIN:
      return (is_packet_queue_empty((struct packet_queue *)mctx->mdata) == 1)
                 ? 0
                 : 1;
    default:
      log_trace("Unknown state");
      return -1;
  }
}

void eloop_tout_pcapfile_handler(void *eloop_ctx, void *user_ctx) {
  struct pcap_stream_context *pctx = (struct pcap_stream_context *)eloop_ctx;
  struct middleware_context *mctx = (struct middleware_context *)user_ctx;

  int ret = process_pcap_stream_state(pctx, mctx);

  if (ret > 0) {
    if (eloop_register_timeout(mctx->eloop, 0, PCAP_READ_INTERVAL,
                               eloop_tout_pcapfile_handler, (void *)pctx,
                               (void *)mctx) == -1) {
      log_error("eloop_register_timeout fail");
      if (pctx->pcap_data != NULL) {
        os_free(pctx->pcap_data);
        pctx->pcap_data = NULL;
      }
      pctx->exit_error = true;
      eloop_terminate(mctx->eloop);
    }
  } else if (ret == 0) {
    log_error("processing fin");
    pctx->exit_error = false;
  } else {
    log_error("process_pcap_stream_state fail");
    pctx->exit_error = true;
  }

  if (ret < 1) {
    if (pctx->pcap_data != NULL) {
      os_free(pctx->pcap_data);
      pctx->pcap_data = NULL;
    }
    eloop_terminate(mctx->eloop);
  }
}

int main(int argc, char *argv[]) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *pcap_path = NULL, *db_path = NULL;
  sqlite3 *db;
  struct eloop_data *eloop;
  struct middleware_context *mctx = NULL;
  struct pcap_stream_context pctx = {.pcap_fd = NULL,
                                     .state = PCAP_STATE_INIT,
                                     .exit_error = false,
                                     .total_size = 0};

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

  if ((mctx = header_middleware.init(db, NULL, eloop, NULL)) == NULL) {
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
      header_middleware.free(mctx);
      return EXIT_FAILURE;
    }

    if (eloop_register_timeout(eloop, 0, PCAP_READ_INTERVAL,
                               eloop_tout_pcapfile_handler, (void *)&pctx,
                               (void *)mctx) == -1) {
      fprintf(stdout, "eloop_register_timeout fail\n");
      eloop_free(eloop);
      os_free(pcap_path);
      sqlite3_close(db);
      header_middleware.free(mctx);
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
  header_middleware.free(mctx);
  if (pctx.exit_error) {
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}
