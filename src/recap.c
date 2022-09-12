/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief A tool to run the capture with an input pcap file
 */

#include <sqlite3.h>
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
#include <inttypes.h>
#include <pcap.h>

#include "utils/os.h"
#include "capture/middlewares/header_middleware/sqlite_header.h"
#include "capture/middlewares/header_middleware/packet_decoder.h"
#include "capture/middlewares/header_middleware/packet_queue.h"

#define RECAP_VERSION_MAJOR 0
#define RECAP_VERSION_MINOR 0
#define RECAP_VERSION_PATCH 1

#define PCAP_READ_INTERVAL 10 // in ms
#define PCAP_READ_SIZE 1024   // bytes
#define IFNAME_DEFAULT "ifname"

#define OPT_STRING ":p:f:i:dhv"
#define USAGE_STRING                                                           \
  "\t%s [-p filename] [-f filename] [-i interface] [-d] [-h] [-v]\n"

#define DESCRIPTION_STRING                                                     \
  "\nRun capture on an input pcap file and output to a capture db.\n"

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   NULL};

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
  sqlite3 *db;
  FILE *pcap_fd;
  char *pcap_data;
  char *ifname;
  ssize_t data_size;
  uint64_t total_size;
  uint64_t npackets;
  enum PCAP_STATE state;
  struct pcap_file_header pcap_header;
  struct pcap_pkthdr32 pkt_header;
};

void show_app_version(void) {
  fprintf(stdout, "recap app version %d.%d.%d\n", EDGESEC_VERSION_MAJOR,
          EDGESEC_VERSION_MINOR, EDGESEC_VERSION_PATCH);
}

void show_app_help(char *app_name) {
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, DESCRIPTION_STRING);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-p filename\t Path to the pcap file name\n");
  fprintf(stdout, "\t-f filename\t Path to the capture db\n");
  fprintf(stdout, "\t-i interface\t Interface name to save to db\n");
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
                         char **pcap_path, char **db_path, char **ifname) {
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
      case 'i':
        *ifname = os_strdup(optarg);
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

void get_packet_header(struct pcap_stream_context *pctx,
                       struct pcap_pkthdr *header) {
  header->ts.tv_sec = pctx->pkt_header.ts_sec;
  header->ts.tv_usec = pctx->pkt_header.ts_usec;
  header->caplen = pctx->pkt_header.caplen;
  header->len = pctx->pkt_header.len;
}

void free_packets(UT_array *packets) {
  struct tuple_packet *p = NULL;
  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    free_packet_tuple(p);
  }
}

int save_sqlite_packet(sqlite3 *db, UT_array *packets) {
  struct tuple_packet *p = NULL;
  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    if (save_packet_statement(db, p) < 0) {
      log_error("save_packet_statement fail");
      return -1;
    }
  }

  return 0;
}

int save_packet(struct pcap_stream_context *pctx) {
  const char *ltype = pcap_datalink_val_to_name(pctx->pcap_header.linktype);
  struct pcap_pkthdr header;
  uint8_t *packet = (uint8_t *)pctx->pcap_data;

  char cap_id[MAX_RANDOM_UUID_LEN];
  generate_radom_uuid(cap_id);
  get_packet_header(pctx, &header);

  int npackets;
  UT_array *packets = NULL;
  utarray_new(packets, &tp_list_icd);

  if ((npackets = extract_packets(ltype, &header, packet, pctx->ifname, cap_id,
                                  packets)) < 0) {
    log_error("extract_packets fail");
    utarray_free(packets);
    return -1;
  }

  log_trace("Decoded %d packets", npackets);

  if (save_sqlite_packet(pctx->db, packets) < 0) {
    log_error("save_sqlite_packet fail");
    free_packets(packets);
    utarray_free(packets);
    return -1;
  }

  pctx->npackets += npackets;

  free_packets(packets);
  utarray_free(packets);
  return 0;
}

int process_pkt_read_state(struct pcap_stream_context *pctx) {
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

    if (save_packet(pctx) < 0) {
      log_error("process_packet fail");
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

int process_pcap_stream_state(struct pcap_stream_context *pctx) {
  log_trace("Processing pcap file stream %zu bytes", pctx->total_size);

  switch (pctx->state) {
    case PCAP_STATE_INIT:
      if ((pctx->pcap_data = os_malloc(sizeof(char))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      pctx->npackets = 0;
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
      if (process_pkt_read_state(pctx) < 0) {
        log_error("process_pkt_read_state fail");
        return -1;
      }
      return 1;
    case PCAP_STATE_FIN:
      return 0;
    default:
      log_trace("Unknown state");
      return -1;
  }
}

int main(int argc, char *argv[]) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *pcap_path = NULL, *db_path = NULL;
  struct pcap_stream_context pctx = {.db = NULL,
                                     .pcap_fd = NULL,
                                     .ifname = NULL,
                                     .state = PCAP_STATE_INIT,
                                     .total_size = 0,
                                     .npackets = 0};

  process_app_options(argc, argv, &verbosity, &pcap_path, &db_path,
                      &pctx.ifname);

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

  if (pctx.ifname == NULL) {
    pctx.ifname = os_strdup(IFNAME_DEFAULT);
  }

  /* Set the log level */
  log_set_level(level);

  int ret = sqlite3_open(db_path, &pctx.db);

  fprintf(stdout, "Openning db at %s\n", db_path);

  if (ret != SQLITE_OK) {
    fprintf(stdout, "Cannot open database: %s", sqlite3_errmsg(pctx.db));
    if (pcap_path != NULL) {
      os_free(pcap_path);
    }
    os_free(db_path);
    os_free(pctx.ifname);
    sqlite3_close(pctx.db);
    return EXIT_FAILURE;
  }

  os_free(db_path);

  if (init_sqlite_header_db(pctx.db) < 0) {
    fprintf(stdout, "init_sqlite_header_db fail\n");
    if (pcap_path != NULL) {
      os_free(pcap_path);
    }
    os_free(pctx.ifname);
    sqlite3_close(pctx.db);
    return EXIT_FAILURE;
  }

  if (pcap_path != NULL) {
    if ((pctx.pcap_fd = fopen(pcap_path, "rb")) == NULL) {
      perror("fopen");
      os_free(pcap_path);
      os_free(pctx.ifname);
      sqlite3_close(pctx.db);
      return EXIT_FAILURE;
    }
  } else {
    pctx.pcap_fd = stdin;
  }

  while ((ret = process_pcap_stream_state(&pctx) > 0)) {
  }

  if (ret < 0) {
    fprintf(stdout, "process_pcap_stream_state fail\n");
    sqlite3_close(pctx.db);
    if (pcap_path != NULL) {
      os_free(pcap_path);
      fclose(pctx.pcap_fd);
    }
    os_free(pctx.ifname);
    return EXIT_FAILURE;
  }

  fprintf(stdout, "Processed pcap size = %" PRIu64 " bytes\n", pctx.total_size);
  fprintf(stdout, "Processed packets = %" PRIu64 "\n", pctx.npackets);

  if (pcap_path != NULL) {
    os_free(pcap_path);
    fclose(pctx.pcap_fd);
  }

  sqlite3_close(pctx.db);
  os_free(pctx.ifname);
  return EXIT_SUCCESS;
}
