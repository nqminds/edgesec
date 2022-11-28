/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief A tool to run the capture with an input pcap file
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pcap.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/types.h>
#include <unistd.h>

#include <eloop.h>

#include "capture/capture_service.h"
#include "capture/middlewares/header_middleware/packet_decoder.h"
#include "capture/middlewares/header_middleware/packet_queue.h"
#include "capture/middlewares/header_middleware/sqlite_header.h"
#include "capture/middlewares/protobuf_middleware/protobuf_middleware.h"
#include "utils/os.h"
#include "utils/sqliteu.h"
#include "version.h"

#define PCAP_MAGIC_VALUE 0xa1b2c3d4
#define QUEUE_PROCESS_INTERVAL 100 * 1000 // In microseconds
#define PCAP_READ_INTERVAL 10             // in ms
#define PCAP_READ_SIZE 1024               // bytes
#define IFNAME_DEFAULT "ifname"

#define OPT_STRING ":p:f:i:tnkdhv"

#define USAGE_STRING                                                           \
  "\t%s [-p filename] [-f filename] [-i interface] [-t] [-n] [-k] [-d] [-h] "  \
  "[-v]\n"

#define DESCRIPTION_STRING                                                     \
  "\nRun capture on an input pcap file, stdin or libpcap and output to a "     \
  "capture db or pipe.\n"

enum PCAP_FILE_STATE {
  PCAP_FILE_STATE_INIT = 0,
  PCAP_FILE_STATE_READ_PCAP_HEADER,
  PCAP_FILE_STATE_READ_PKT_HEADER,
  PCAP_FILE_STATE_READ_PACKET,
  PCAP_FILE_STATE_FIN
};

struct pcap_pkthdr32 {
  uint32_t ts_sec;  /* timestamp seconds.*/
  uint32_t ts_usec; /* timestamp microseconds.*/
  uint32_t caplen;  /* length of portion present */
  uint32_t len;     /* length this packet (off wire) */
} STRUCT_PACKED;

struct recap_context {
  sqlite3 *db;
  int pipe_fd;
  FILE *pcap_fd;
  struct packet_queue *pq;
  char *pcap_data;
  char *ifname;
  char *out_path;
  ssize_t data_size;
  uint64_t total_size;
  uint64_t npackets;
  enum PCAP_FILE_STATE state;
  struct pcap_file_header pcap_header;
  struct pcap_pkthdr32 pkt_header;
  bool pipe;
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
  fprintf(stdout, "\t-p filename\t Path to the pcap file name.\n");
  fprintf(stdout, "\t-f filename\t Path to the capture db or pipe.\n");
  fprintf(
      stdout,
      "\t-i interface\t Interface name to save to db or to capture from.\n");
  fprintf(stdout, "\t-t\t\t Use a single SQLITE transaction.\n");
  fprintf(stdout, "\t-n\t\t Capture from network stream.\n");
  fprintf(stdout, "\t-k\t\t Pipe to file.\n");
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
  fflush(stderr);

  fprintf(stderr, "Command-line usage error: ");
  va_start(argList, format);
  vfprintf(stderr, format, argList);
  va_end(argList);

  fflush(stderr); /* In case stderr is not line-buffered */
  exit(EXIT_FAILURE);
}

void process_app_options(int argc, char *argv[], uint8_t *verbosity,
                         char **pcap_path, char **out_path, char **ifname,
                         bool *pipe, bool *capture, bool *transaction) {
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
        *capture = true;
        break;
      case 'k':
        *pipe = true;
        break;
      case 'd':
        (*verbosity)++;
        break;
      case 't':
        *transaction = true;
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

ssize_t read_pcap_stream_fd(struct recap_context *pctx, size_t len,
                            char **data) {
  if ((*data = os_malloc(len)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  return (ssize_t)fread(*data, sizeof(char), len, pctx->pcap_fd);
}

ssize_t read_pcap(struct recap_context *pctx, size_t len) {
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

int process_file_header_state(struct recap_context *pctx) {
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

    log_trace("\tpcap_file_header magic = %x", pctx->pcap_header.magic);
    log_trace("\tpcap_file_header version_major = %d",
              pctx->pcap_header.version_major);
    log_trace("\tpcap_file_header version_minor = %d",
              pctx->pcap_header.version_minor);
    log_trace("\tpcap_file_header thiszone = %" PRId32,
              pctx->pcap_header.thiszone);
    log_trace("\tpcap_file_header snaplen = %" PRIu32,
              pctx->pcap_header.snaplen);
    log_trace("\tpcap_file_header linktype = %" PRIu32,
              pctx->pcap_header.linktype);
    pctx->data_size = 0;

    if (pctx->pcap_header.magic != PCAP_MAGIC_VALUE) {
      log_error(
          "Not a pcap file (magic number error), perhaps a pcapng file!!!");
      return -1;
    }
    pctx->state = PCAP_FILE_STATE_READ_PKT_HEADER;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_FILE_STATE_FIN;
  }

  return 0;
}

int process_pkt_header_state(struct recap_context *pctx) {
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
    pctx->state = PCAP_FILE_STATE_READ_PACKET;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_FILE_STATE_FIN;
  }

  return 0;
}

void get_packet_header(struct recap_context *pctx, struct pcap_pkthdr *header) {
  header->ts.tv_sec = pctx->pkt_header.ts_sec;
  header->ts.tv_usec = pctx->pkt_header.ts_usec;
  header->caplen = pctx->pkt_header.caplen;
  header->len = pctx->pkt_header.len;
}

int save_sqlite_tuple_packet(sqlite3 *db, struct tuple_packet *p) {
  if (save_packet_statement(db, p) < 0) {
    log_error("save_packet_statement fail");
    return -1;
  }

  return 0;
}

int save_sqlite_packet(sqlite3 *db, UT_array *packets) {
  struct tuple_packet *p = NULL;
  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    if (save_sqlite_tuple_packet(db, p) < 0) {
      log_error("save_sqlite_tuple_packet fail");
      return -1;
    }
  }

  return 0;
}

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL,
                                   free_packet};

int save_packet_array(struct recap_context *pctx, UT_array *packets) {
  if (pctx->pipe) {
    if (pipe_protobuf_packets(pctx->out_path, &pctx->pipe_fd, packets) < 0) {
      log_error("pipe_protobuf_packets fail");
      return -1;
    }
  } else {
    if (save_sqlite_packet(pctx->db, packets) < 0) {
      log_error("save_sqlite_packet fail");
      return -1;
    }
  }

  return 0;
}

int save_tuple_packet(struct recap_context *pctx, struct tuple_packet *p) {
  if (pctx->pipe) {
    if (pipe_protobuf_tuple_packet(pctx->out_path, &pctx->pipe_fd, p) < 0) {
      log_error("pipe_protobuf_tuple_packet fail");
      return -1;
    }
  } else {
    if (save_sqlite_tuple_packet(pctx->db, p) < 0) {
      log_error("save_sqlite_tuple_packet fail");
      return -1;
    }
  }

  return 0;
}

int save_decoded_packet(const char *ltype, const struct pcap_pkthdr *header,
                        const uint8_t *packet, char *ifname,
                        struct recap_context *pctx) {
  UT_array *packets = NULL;
  utarray_new(packets, &tp_list_icd);

  int npackets = extract_packets(ltype, header, packet, ifname, packets);
  if (npackets < 0) {
    log_error("extract_packets fail");
    utarray_free(packets);
    return -1;
  }

  log_trace("Decoded %d packets", npackets);
  if (save_packet_array(pctx, packets) < 0) {
    log_error("save_packet_array fail");
    utarray_free(packets);
    return -1;
  }

  utarray_free(packets);
  return npackets;
}

int save_raw_packet(struct recap_context *pctx) {
  const char *ltype = pcap_datalink_val_to_name(pctx->pcap_header.linktype);
  uint8_t *packet = (uint8_t *)pctx->pcap_data;

  struct pcap_pkthdr header;
  get_packet_header(pctx, &header);

  int npackets =
      save_decoded_packet(ltype, &header, packet, pctx->ifname, pctx);
  if (npackets < 0) {
    log_error("save_decoded_packet fail");
    return -1;
  }

  pctx->npackets += npackets;

  return 0;
}

int process_pkt_read_state(struct recap_context *pctx) {
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

    if (save_raw_packet(pctx) < 0) {
      log_error("process_packet fail");
      return -1;
    }

    pctx->data_size = 0;
    pctx->state = PCAP_FILE_STATE_READ_PKT_HEADER;
  } else if (read_size == 0) {
    log_trace("No data received");
    pctx->state = PCAP_FILE_STATE_FIN;
  }

  return 0;
}

int process_file_stream_state(struct recap_context *pctx) {
  log_trace("Processing file stream %zu bytes", pctx->total_size);

  switch (pctx->state) {
    case PCAP_FILE_STATE_INIT:
      if ((pctx->pcap_data = os_malloc(sizeof(char))) == NULL) {
        log_errno("os_malloc");
        return -1;
      }
      pctx->npackets = 0;
      pctx->total_size = 0;
      pctx->data_size = 0;
      pctx->state = PCAP_FILE_STATE_READ_PCAP_HEADER;
      return 1;
    case PCAP_FILE_STATE_READ_PCAP_HEADER:
      if (process_file_header_state(pctx) < 0) {
        log_error("process_file_header_state fail");
        return -1;
      }
      return 1;
    case PCAP_FILE_STATE_READ_PKT_HEADER:
      if (process_pkt_header_state(pctx) < 0) {
        log_error("process_pkt_header_state fail");
        return -1;
      }
      return 1;
    case PCAP_FILE_STATE_READ_PACKET:
      if (process_pkt_read_state(pctx) < 0) {
        log_error("process_pkt_read_state fail");
        return -1;
      }
      return 1;
    case PCAP_FILE_STATE_FIN:
      return 0;
    default:
      log_trace("Unknown state");
      return -1;
  }
}

int process_file_stream(const char *pcap_path, struct recap_context *pctx) {
  if (pcap_path != NULL) {
    if ((pctx->pcap_fd = fopen(pcap_path, "rb")) == NULL) {
      log_errno("fopen failed for pcap file %s", pcap_path);
      return -1;
    }
  } else {
    pctx->pcap_fd = stdin;
  }

  int ret;
  while ((ret = process_file_stream_state(pctx) > 0)) {
  }

  if (ret < 0) {
    log_error("process_file_stream_state fail");
    return -1;
  }

  return 0;
}

void add_packet_queue(UT_array *packets, struct packet_queue *queue) {
  struct tuple_packet *p = NULL;

  while ((p = (struct tuple_packet *)utarray_next(packets, p)) != NULL) {
    if (push_packet_queue(queue, *p) == NULL) {
      // Free the packet if cannot be added to the queue
      free_packet_tuple(p);
    }
  }
}

void pcap_callback(const void *ctx, const void *pcap_ctx, char *ltype,
                   struct pcap_pkthdr *header, uint8_t *packet) {

  (void)pcap_ctx;

  struct pcap_context *pc = (struct pcap_context *)pcap_ctx;
  struct pcap_stat ps;

  if (get_pcap_stats(pc, &ps) == 0) {
    log_trace("ps_recv=%d ps_drop=%d ps_ifdrop=%d", ps.ps_recv, ps.ps_drop,
              ps.ps_ifdrop);
  }

  struct recap_context *pctx = (struct recap_context *)ctx;

  UT_array *packets = NULL;
  utarray_new(packets, &tp_list_icd);

  int npackets = extract_packets(ltype, header, packet, pctx->ifname, packets);

  if (npackets > 0) {
    add_packet_queue(packets, pctx->pq);
    pctx->npackets += npackets;
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

void save_packets_from_queue(struct recap_context *pctx) {
  struct packet_queue *el = NULL;
  while (is_packet_queue_empty(pctx->pq) < 1) {
    if ((el = pop_packet_queue(pctx->pq)) != NULL) {
      if (save_tuple_packet(pctx, &(el->tp)) < 0) {
        log_error("save_tuple_packet fail");
      }

      free_packet_tuple(&el->tp);
      free_packet_queue_el(el);
    }
  }
}

void eloop_tout_header_handler(void *eloop_ctx, void *user_ctx) {
  struct recap_context *pctx = (struct recap_context *)user_ctx;

  if (is_packet_queue_empty(pctx->pq) < 1) {
    log_trace("Commiting packets to %s database", pctx->out_path);
    if (execute_sqlite_query(pctx->db, "BEGIN IMMEDIATE TRANSACTION") < 0) {
      log_error("Failed to capture a lock on db %s, ignoring.", pctx->out_path);
    }

    save_packets_from_queue(pctx);

    if (execute_sqlite_query(pctx->db, "COMMIT TRANSACTION") < 0) {
      log_error("Failed to commit packets to database %s", pctx->out_path);
    }
  }

  struct eloop_data *eloop = (struct eloop_data *)eloop_ctx;
  if (eloop_register_timeout(eloop, 0, QUEUE_PROCESS_INTERVAL,
                             eloop_tout_header_handler, eloop,
                             (void *)pctx) == -1) {
    log_error("eloop_register_timeout fail");
  }
}

int process_pcap_capture(struct recap_context *pctx) {
  struct eloop_data *eloop = NULL;
  int exit_code = -1;
  struct pcap_context *pc = NULL;

  if ((eloop = eloop_init()) == NULL) {
    log_error("eloop_init fail");
    goto process_pcap_capture_fail;
  }
  if (run_pcap(pctx->ifname, false, false, 10, NULL, true, pcap_callback,
               (void *)pctx, &pc) < 0) {
    log_error("run_pcap fail");
    goto process_pcap_capture_fail;
  }

  if (pc != NULL) {
    if ((pctx->pq = init_packet_queue()) == NULL) {
      log_error("init_packet_queue fail");
      goto process_pcap_capture_fail;
    }

    if (eloop_register_read_sock(eloop, pc->pcap_fd, eloop_read_fd_handler,
                                 (void *)pc, (void *)NULL) == -1) {
      log_error("eloop_register_read_sock fail");
      goto process_pcap_capture_fail;
    }

    if (eloop_register_timeout(eloop, 0, QUEUE_PROCESS_INTERVAL,
                               eloop_tout_header_handler, eloop,
                               (void *)pctx) == -1) {
      log_error("eloop_register_timeout fail");
      goto process_pcap_capture_fail;
    }
  } else {
    log_error("Empty pcap context");
    goto process_pcap_capture_fail;
  }

  eloop_run(eloop);

  exit_code = 0;

process_pcap_capture_fail:
  eloop_free(eloop);
  close_pcap(pc);
  free_packet_queue(pctx->pq);
  return exit_code;
}

int main(int argc, char *argv[]) {
  int exit_code = EXIT_FAILURE;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *pcap_path = NULL;
  bool capture = false;
  bool transaction = false;
  struct recap_context pctx = {.db = NULL,
                               .pipe_fd = -1,
                               .pcap_fd = NULL,
                               .pq = NULL,
                               .ifname = NULL,
                               .out_path = NULL,
                               .state = PCAP_FILE_STATE_INIT,
                               .total_size = 0,
                               .npackets = 0,
                               .pipe = false};

  process_app_options(argc, argv, &verbosity, &pcap_path, &pctx.out_path,
                      &pctx.ifname, &pctx.pipe, &capture, &transaction);
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

  if (!pctx.pipe) {
    int ret = sqlite3_open(pctx.out_path, &pctx.db);

    fprintf(stdout, "Opened db at %s\n", pctx.out_path);

    if (ret != SQLITE_OK) {
      fprintf(stdout, "Cannot open database: %s", sqlite3_errmsg(pctx.db));
      goto cleanup;
    }

    if (init_sqlite_header_db(pctx.db) < 0) {
      fprintf(stderr, "init_sqlite_header_db fail\n");
      goto cleanup;
    }

    // Begin transaction is used by default in capture
    if (transaction && !capture) {
      fprintf(stdout, "Using transaction mode\n");
      if (execute_sqlite_query(pctx.db, "BEGIN IMMEDIATE TRANSACTION") < 0) {
        fprintf(stderr,
                "Failed to capture a lock on db %s, please retry this "
                "command later",
                pctx.out_path);
        goto cleanup;
      }
    }
  } else {
    if (create_pipe_file(pctx.out_path) < 0) {
      fprintf(stderr, "create_pipe_file fail");
      goto cleanup;
    }

    fprintf(stdout, "Created pipe file at %s\n", pctx.out_path);
  }

  if (!capture) {
    if (process_file_stream(pcap_path, &pctx) < 0) {
      fprintf(stderr, "process_file_stream fail");
      goto cleanup;
    }
  } else {
    fprintf(stdout, "Registering pcap capture for ifname=%s", pctx.ifname);
    if (process_pcap_capture(&pctx) < 0) {
      fprintf(stderr, "process_pcap_capture fail");
      goto cleanup;
    }
  }

  if (!capture) {
    fprintf(stdout, "Processed pcap file/stream size = %" PRIu64 " bytes\n",
            pctx.total_size);
  }
  fprintf(stdout, "Processed packets = %" PRIu64 "\n", pctx.npackets);

  if (pctx.db != NULL && !capture) {
    // If AUTOCOMMIT is disabled, we need to manually make a COMMIT
    if (sqlite3_get_autocommit(pctx.db) == 0) {
      fprintf(stdout, "Commiting changes to %s database\n", pctx.out_path);
      if (execute_sqlite_query(pctx.db, "COMMIT TRANSACTION") < 0) {
        fprintf(stderr, "Failed to commit %" PRIu64 " packets to database %s",
                pctx.npackets, pctx.out_path);
        goto cleanup;
      }
    }
  }

  // success!
  exit_code = EXIT_SUCCESS;

cleanup:
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
