// Set the environment variable ENV_DB_KEY=dbpath:dbprefix
// Use SELECT load_extension("./src/libsqlhook.so"); to load the extension
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
#include <utarray.h>

#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/sockctl.h"

SQLITE_EXTENSION_INIT1

#define SOCK_EXTENSION ".sock"
#define ENV_DB_KEY "EDGESEC"
#define DOMAIN_ID_STR "domain"
#define DELIMITER_CHAR '_'

struct dir_ctx {
  UT_array *domain_sockets;
  UT_array *ports;
};

static char sock_path[MAX_OS_PATH_LEN];
static int domain_fd = -1;
static int udp_fd = -1;

bool list_dir_function(char *path, void *args) {
  struct dir_ctx *ctx = (struct dir_ctx *)args;
  char *filename, *del, port_str[6];
  int port;

  if (strstr(path, SOCK_EXTENSION)) {
    if ((filename = basename(path)) != NULL) {
      if (strstr(filename, DOMAIN_ID_STR)) {
        utarray_push_back(ctx->domain_sockets, &path);
      } else {
        if ((del = strchr(filename, DELIMITER_CHAR)) != NULL) {
          port = (int)(del - filename);
          if (port > 0 && port < 6) {
            os_memcpy(port_str, filename, port);
            port_str[port] = '\0';

            errno = 0;
            port = (int)strtol(port_str, NULL, 10);
            if (errno != EINVAL) {
              utarray_push_back(ctx->ports, &port);
            }
          }
        }
      }
    }
  }

  return true;
}

int get_dir_file_sockets(struct dir_ctx *ctx) {
  utarray_new(ctx->domain_sockets, &ut_str_icd);
  utarray_new(ctx->ports, &ut_int_icd);

  if (list_dir(sock_path, list_dir_function, (void *)ctx) < 0) {
    utarray_free(ctx->domain_sockets);
    utarray_free(ctx->ports);
    return -1;
  }

  return 0;
}

void send_domain_message(char *path, char *message) {
  write_domain_data_s(domain_fd, message, strlen(message), path);
}

int create_udp_client(void) {
  int sockfd;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  return sockfd;
}

void send_udp_message(int port, char *message) {
  struct sockaddr_in servaddr;

  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  servaddr.sin_addr.s_addr = INADDR_ANY;

  sendto(udp_fd, message, strlen(message), 0,
         (const struct sockaddr *)&servaddr, sizeof(servaddr));
}

void update_hook(void *data, int type, char const *database, char const *table,
                 sqlite3_int64 rowid) {
  (void)data;
  (void)database;

  char **domain = NULL;
  int *port = NULL;
  char message[256];

  struct dir_ctx ctx = {NULL, NULL};

  log_set_quiet(false);

  snprintf(message, 255, "%lld %d %s\n", rowid, type, table);

  if (get_dir_file_sockets(&ctx) < 0) {
    return;
  }

  while ((domain = (char **)utarray_next(ctx.domain_sockets, domain))) {
    send_domain_message(*domain, message);
  }

  while ((port = (int *)utarray_next(ctx.ports, port))) {
    send_udp_message(*port, message);
  }

  utarray_free(ctx.domain_sockets);
  utarray_free(ctx.ports);
}

#ifdef _WIN32
__declspec(dllexport)
#endif
    /* TODO: Change the entry point name so that "extension" is replaced by
    ** text derived from the shared library filename as follows:  Copy every
    ** ASCII alphabetic character from the filename after the last "/" through
    ** the next following ".", converting each character to lowercase, and
    ** discarding the first three characters if they are "lib".
    */
    int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg,
                               const sqlite3_api_routines *pApi) {
  (void)pzErrMsg;

  char *env_key_value;
  int rc = SQLITE_OK;

  SQLITE_EXTENSION_INIT2(pApi);

  if ((env_key_value = getenv(ENV_DB_KEY)) == NULL) {
    return rc;
  }

  strncpy(sock_path, env_key_value, MAX_OS_PATH_LEN);

  if ((domain_fd = create_domain_client(NULL)) < 0) {
    return rc;
  }

  if ((udp_fd = create_udp_client()) < 0) {
    close(domain_fd);
    return rc;
  }

  sqlite3_update_hook(db, update_hook, NULL);

  return rc;
}
