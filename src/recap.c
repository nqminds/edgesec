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

#include <eloop.h>

#include "version.h"
#include "utils/os.h"
#include "capture/middlewares/header_middleware/sqlite_header.h"
#include "capture/middlewares/header_middleware/packet_decoder.h"
#include "capture/middlewares/header_middleware/packet_queue.h"
#include "capture/middlewares/protobuf_middleware/protobuf_middleware.h"
#include "capture/capture_service.h"
#include "utils/sqliteu.h"

#define PCAP_READ_INTERVAL 10 // in ms
#define PCAP_READ_SIZE 1024   // bytes
#define IFNAME_DEFAULT "ifname"

#define OPT_STRING ":p:f:i:t:skdhv"

#define USAGE_STRING                                                           \
  "\t%s [-p filename] [-f filename] [-i interface] [-n] [-k] [-d] [-h] [-v]\n"      \
  "\t\t [-t {SINGLE_TRANSACTION,DISABLED}]"

#define DESCRIPTION_STRING                                                     \
  "\nRun capture on an input pcap file, stdin or libpcap and output to a capture db or pipe.\n"

enum PCAP_STATE {
  PCAP_STATE_INIT = 0,
  PCAP_STATE_READ_PCAP_HEADER,
  PCAP_STATE_READ_PKT_HEADER,
  PCAP_STATE_READ_PACKET,
  PCAP_STATE_FIN
};

/**
 * @brief SQLITE_TRANSACTION_TYPE
 *
 * Decides how to insert data into the SQLITE database.
 */
enum SQLITE_TRANSACTION_TYPE {
  /**
   * @brief Runs the entire `recap` process in a single SQLITE transaction.
   *
   * This is the recommend option for maximum insertion performance. However,
   * it does mean that nobody else can access the database while inserting data.
   */
  SINGLE_TRANSACTION = -1,
  /**
   * @brief Automatically picks an SQLITE_TRANSACTION_TYPE based on the input
   * data by default.
   *
   * This is using a single SQLITE transaction when importing from a pcap file.
   */
  DEFAULT = 0,
  /**
   * @brief Disables SQLITE transactions.
   *
   * Each SQLITE insertion makes it's own transaction. Not recommended unless
   * the input stream is throttled, as this will be very slow
   * (e.g. 3000x slower that a SINGLE_TRANSACTION).
   */
  DISABLED,
};

struct pcap_pkthdr32 {
  uint32_t ts_sec;  /* timestamp seconds.*/
  uint32_t ts_usec; /* timestamp microseconds.*/
  uint32_t caplen;  /* length of portion present */
  uint32_t len;     /* length this packet (off wire) */
} STRUCT_PACKED;

struct pcap_stream_context {
  sqlite3 *db;
  int pipe_fd;
  FILE *pcap_fd;
  char *pcap_data;
  char *ifname;
  char *out_path;
  ssize_t data_size;
  uint64_t total_size;
  uint64_t npackets;
  enum PCAP_STATE state;
  struct pcap_file_header pcap_header;
  struct pcap_pkthdr32 pkt_header;
  int pipe;
};

void show_app_version(void) {
  fprintf(stdout, "recap app version %s\n", EDGESEC_VERSION);
}

void show_app_help(char *app_name) {
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, DESCRIPTION_STRING);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-p filename\t Path to the pcap file name\n");
  fprintf(stdout, "\t-f filename\t Path to the capture db or pipe\n");
  fprintf(stdout, "\t-i interface\t Interface name to save to db\n");
  fprintf(stdout,
          "\t-t TRANS_TYPE\t Controls how SQLITE transactions are used.\n");
  fprintf(stdout, "\t             \t Allowed values:\n");
  fprintf(stdout, "\t             \t   SINGLE_TRANSACTION: Use a single SQLITE "
                  "transaction.\n");
  fprintf(stdout,
          "\t             \t   \t Provides maximum insertion performance.\n");
  fprintf(stdout, "\t             \t   DISABLED: Don't use SQLITE transactions "
                  "(very slow).\n");
  fprintf(stdout,
          "\t             \t   (default) Pick automatically based on input.\n");
  fprintf(stdout, "\t-n\t\t Capture from network stream.\n");
  fprintf(stdout, "\t-k\t\t Pipe to file\n");
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

void process_app_options(
    int argc, char *argv[], uint8_t *verbosity, char **pcap_path,
    char **out_path, char **ifname, int *pipe, int *capture,
    enum SQLITE_TRANSACTION_TYPE *sqlite_transaction_type) {
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
        *out_path = os_strdup(optarg);
        break;
      case 'i':
        *ifname = os_strdup(optarg);
        break;
      case 'n':
        *capture = 1;
        break;
      case 'k':
        *pipe = 1;
        break;
      case 'd':
        (*verbosity)++;
        break;
      case 't':
        if (strcmp("SINGLE_TRANSACTION", optarg) == 0) {
          *sqlite_transaction_type = SINGLE_TRANSACTION;
        } else if (strcmp("DISABLED", optarg) == 0) {
          *sqlite_transaction_type = DISABLED;
        } else {
          log_cmdline_error("argument t: invalid choice %s (choose from "
                            "SINGLE_TRANSACTION, DISABLED)",
                            optarg);
        }
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
  ssize_t read_size = read_pcap_stream_fd(pctx, len, &data);
  if (read_size < 0) {
    log_error("read_pcap_stream_fd fail");
    return -1;
  }

  pctx->total_size += read_size;

  ssize_t current_size = read_size + pctx->data_size;

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
  ssize_t pcap_header_size = (ssize_t)sizeof(struct pcap_file_header);

  size_t len = (pcap_header_size > pctx->data_size)
                   ? pcap_header_size - pctx->data_size
                   : 0;

  ssize_t read_size = read_pcap(pctx, len);
  if (read_size < 0) {
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

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   free_packet};

int save_packet_data(const char *ltype, const struct pcap_pkthdr *header,
                    const uint8_t *packet, char *ifname, char *id,
                    struct pcap_stream_context *pctx) {
  UT_array *packets = NULL;
  utarray_new(packets, &tp_list_icd);

  int npackets =
      extract_packets(ltype, header, packet, ifname, id, packets);
  if (npackets < 0) {
    log_error("extract_packets fail");
    utarray_free(packets);
    return -1;
  }

  log_trace("Decoded %d packets", npackets);

  if (pctx->pipe) {
    if (pipe_protobuf_packets(pctx->out_path, &pctx->pipe_fd, packets) < 0) {
      log_error("pipe_protobuf_packets fail");
      utarray_free(packets);
      return -1;
    }
  } else {
    if (save_sqlite_packet(pctx->db, packets) < 0) {
      log_error("save_sqlite_packet fail");
      utarray_free(packets);
      return -1;
    }
  }

  utarray_free(packets);
  return npackets;
}

int save_packet(struct pcap_stream_context *pctx) {
  const char *ltype = pcap_datalink_val_to_name(pctx->pcap_header.linktype);
  uint8_t *packet = (uint8_t *)pctx->pcap_data;

  char cap_id[MAX_RANDOM_UUID_LEN];
  generate_radom_uuid(cap_id);

  struct pcap_pkthdr header;
  get_packet_header(pctx, &header);

  int npackets = save_packet_data(ltype, &header,
                    packet, pctx->ifname, cap_id,
                    pctx);
  if (npackets < 0) {
    log_error("save_packet_data fail");
    return -1;
  }

  pctx->npackets += npackets;

  return 0;
}

int process_pkt_read_state(struct pcap_stream_context *pctx) {
  size_t len = ((ssize_t)pctx->pkt_header.caplen > pctx->data_size)
                   ? pctx->pkt_header.caplen - pctx->data_size
                   : 0;

  ssize_t read_size = read_pcap(pctx, len);
  if (read_size < 0) {
    log_error("read_pcap fail");
    return -1;
  }

  if (pctx->data_size >= (ssize_t)pctx->pkt_header.caplen) {
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

int process_pcap_stream(const char *pcap_path, struct pcap_stream_context *pctx) {
  if (pcap_path != NULL) {
    if ((pctx->pcap_fd = fopen(pcap_path, "rb")) == NULL) {
      log_errno("fopen failed for pcap file %s", pcap_path);
      return -1;
    }
  } else {
    pctx->pcap_fd = stdin;
  }

  int ret;
  while ((ret = process_pcap_stream_state(pctx) > 0)) {
  }

  if (ret < 0) {
    log_error("process_pcap_stream_state fail");
    return -1;
  }

  return 0;
}

void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet) {

  (void)pcap_ctx;

  struct pcap_context *pc = (struct pcap_context *) pcap_ctx;
  struct pcap_stat ps;

  if (get_pcap_stats(pc, &ps) == 0) {
    log_trace("ps_recv=%d ps_drop=%d ps_ifdrop=%d", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
  }

  struct pcap_stream_context *context =
    (struct pcap_stream_context *)ctx;

  char cap_id[MAX_RANDOM_UUID_LEN];
  generate_radom_uuid(cap_id);

  if (save_packet_data(ltype, header,
                    packet, context->ifname, cap_id,
                    context) < 0) {
    log_trace("save_packet_data fail");
  }
}

void eloop_read_fd_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)sock;
  (void)sock_ctx;

  struct pcap_context *pc = (struct pcap_context *)eloop_ctx;

  if (capture_pcap_packet(pc) < 0) {
    log_trace("capture_pcap_packet fail");
  }
}

int main(int argc, char *argv[]) {
  int exit_code = EXIT_FAILURE;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *pcap_path = NULL;
  int capture = 0;
  struct pcap_stream_context pctx = {.db = NULL,
                                     .pipe_fd = -1,
                                     .pcap_fd = NULL,
                                     .ifname = NULL,
                                     .out_path = NULL,
                                     .state = PCAP_STATE_INIT,
                                     .total_size = 0,
                                     .npackets = 0,
                                     .pipe = 0};
  enum SQLITE_TRANSACTION_TYPE sqlite_transaction_type = DEFAULT;

  process_app_options(argc, argv, &verbosity, &pcap_path, &pctx.out_path,
                      &pctx.ifname, &pctx.pipe, &capture, &sqlite_transaction_type);
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

  if (sqlite_transaction_type == DEFAULT) {
    sqlite_transaction_type = SINGLE_TRANSACTION;
  }

  if (!pctx.pipe) {
    int ret = sqlite3_open(pctx.out_path, &pctx.db);

    fprintf(stdout, "Opened db at %s\n", pctx.out_path);

    if (ret != SQLITE_OK) {
      fprintf(stdout, "Cannot open database: %s", sqlite3_errmsg(pctx.db));
      goto cleanup;
    }

    if (init_sqlite_header_db(pctx.db) < 0) {
      fprintf(stdout, "init_sqlite_header_db fail\n");
      goto cleanup;
    }

    if (sqlite_transaction_type == SINGLE_TRANSACTION) {
      if (execute_sqlite_query(pctx.db, "BEGIN IMMEDIATE TRANSACTION") < 0) {
        log_error("Failed to capture a lock on db %s, please retry this "
                  "command later",
                  pctx.out_path);
        goto cleanup;
      }
    }
  } else {
    if (create_pipe_file(pctx.out_path) < 0) {
      log_error("create_pipe_file fail");
      goto cleanup;
    }

    fprintf(stdout, "Created pipe file at %s\n", pctx.out_path);
  }

  struct pcap_context *pc = NULL;
  struct eloop_data *eloop = NULL;
  if (!capture) {
    if (process_pcap_stream(pcap_path, &pctx) < 0) {
      fprintf(stdout, "process_pcap_stream fail");
      goto cleanup;
    }
  } else {
    if ((eloop = eloop_init()) == NULL) {
      fprintf(stdout, "eloop_init fail");
      goto cleanup;
    }

    fprintf(stdout, "Registering pcap for ifname=%s", pctx.ifname);
    if (run_pcap(pctx.ifname, false, false, 10,
                 NULL, true, pcap_callback, (void *)&pctx,
                 &pc) < 0) {
      fprintf(stdout, "run_pcap fail");
      goto cleanup;
    }

    if (pc != NULL) {
      if (eloop_register_read_sock(eloop, pc->pcap_fd, eloop_read_fd_handler,
                                   (void *)pc, (void *)NULL) == -1) {
        fprintf(stdout, "eloop_register_read_sock fail");
        goto cleanup;
      }
    } else {
      fprintf(stdout, "Empty pcap context");
      goto cleanup;
    }

    eloop_run(eloop);
  }

  fprintf(stdout, "Processed pcap size = %" PRIu64 " bytes\n", pctx.total_size);
  fprintf(stdout, "Processed packets = %" PRIu64 "\n", pctx.npackets);

  if (pctx.db != NULL) {
    // If AUTOCOMMIT is disabled, we need to manually make a COMMIT
    if (sqlite3_get_autocommit(pctx.db) == 0) {
      log_info("Commiting changes to %s database", pctx.out_path);
      if (execute_sqlite_query(pctx.db, "COMMIT TRANSACTION") < 0) {
        log_error("Failed to commit %" PRIu64 " packets to database %s",
                  pctx.npackets, pctx.out_path);
        goto cleanup;
      }
    }
  }

  // success!
  exit_code = EXIT_SUCCESS;

cleanup:
  eloop_free(eloop);
  close_pcap(pc);
  os_free(pctx.ifname);
  if (pcap_path != NULL) {
    os_free(pcap_path);
    fclose(pctx.pcap_fd);
  }

  os_free(pctx.out_path);
  // sqlite3 close on a NULL ptr is fine
  // any uncommited transactions will be automatically rolled-back on close
  sqlite3_close(pctx.db);
  os_free(pctx.ifname);

  return exit_code;
}
