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
 * @file restsrv.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the rest server app.
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
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

#include "crypt/crypt_service.h"
#include "supervisor/cmd_processor.h"
#include "ap/ap_service.h"
#include "microhttpd.h"
#include "version.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/log.h"
#include "utils/minIni.h"
#include "utils/domain.h"
#include "utils/cryptou.h"

#define SOCK_PACKET_SIZE 10

#define OPT_STRING    ":a:s:p:z:c:u:tdvh"
#define USAGE_STRING  "\t%s [-s address] [-a address] [-p port] [-z delim] [-c path] [-u passphrase] [-t] [-d] [-h] [-v]\n"

#define JSON_RESPONSE_OK "{\"cmd\":\"%s\",\"response\":[%s]}"
#define JSON_RESPONSE_FAIL "{\"error\":\"invalid get request\"}"

#define MESSAGE_REPLY_TIMEOUT 10  // In seceonds
// char *socket_path = "\0hidden";

static __thread char version_buf[10];

struct socket_address {
  char apath[MAX_OS_PATH_LEN];
  char spath[MAX_OS_PATH_LEN];
  char delim;
};

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
  fprintf(stdout, "restsrv app version %s\n",
    get_static_version_string(RESTSRV_VERSION_MAJOR, RESTSRV_VERSION_MINOR,
                              RESTSRV_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-s address\t Path to supervisor socket\n");
  fprintf(stdout, "\t-a address\t Path to AP socket\n");
  fprintf(stdout, "\t-p port\t\t Server port\n");
  fprintf(stdout, "\t-z delim\t\t Command delimiter\n");
  fprintf(stdout, "\t-c path\t\t The crypt db path\n");
  fprintf(stdout, "\t-u passphrase\t\t The user passpharse\n");
  fprintf(stdout, "\t-t\t\t Use TLS\n");
  fprintf(stdout, "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright NQMCyber Ltd\n\n");
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

int get_port(char *port_str)
{
  if (!is_number(port_str))
    return -1;
  
  return strtol(port_str, NULL, 10);
}

void process_app_options(int argc, char *argv[], char *spath, char *apath,
  int *port, char *delim, bool *tls, char ** db_path, char **passphrase, uint8_t *verbosity)
{
  int opt;
  int p;
  *tls = false;
  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
    case 'c':
      *db_path = os_strdup(optarg);
      break;
    case 'u':
      *passphrase = os_strdup(optarg);
      break;
    case 't':
      *tls = true;
      break;
    case 'd':
      (*verbosity)++;
      break;
    case 'h':
      show_app_help(argv[0]);
      break;
    case 'v':
      show_app_version();
      exit(EXIT_SUCCESS);
      break;
    case 's':
      os_strlcpy(spath, optarg, MAX_OS_PATH_LEN);
      break;
    case 'a':
      os_strlcpy(apath, optarg, MAX_OS_PATH_LEN);
      break;
    case 'z':
      errno = 0;
      *delim = strtol(optarg, NULL, 10);
      if (errno == EINVAL || errno == ERANGE || !*delim) {
        log_cmdline_error("Unrecognized delim value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'p':
      if ((p = get_port(optarg)) < 0) {
        log_cmdline_error("Unrecognized port value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      *port = p;
      break;
    case ':':
      log_cmdline_error("Missing argument for -%c\n", optopt);
      exit(EXIT_FAILURE);
    case '?':
      log_cmdline_error("Unrecognized option -%c\n", optopt);
      exit(EXIT_FAILURE);
    default: show_app_help(argv[0]);
    }
  }
}


int print_out_key (void *cls, enum MHD_ValueKind kind, 
                   const char *key, const char *value)
{
  log_info("HEADER --> key=%s value=%s", key, value);
  return MHD_YES;
}

char* create_command_string(char *cmd, char *args, char *cmd_str, char delim)
{
  char *cmd_tmp;
  if (cmd == NULL || cmd_str == NULL)
    return NULL;

  if (os_strnlen_s(cmd, MAX_SUPERVISOR_CMD_SIZE)) {
    cmd_tmp = os_strdup(cmd);
    upper_string(cmd_tmp);
    if (args ==  NULL)
      sprintf(cmd_str, "%s", cmd_tmp);
    else
      sprintf(cmd_str, "%s %s", cmd_tmp, args);
    replace_string_char(cmd_str, ',', delim);
    os_free(cmd_tmp);

    return cmd_str;
  }

  return NULL;
}

enum MHD_Result create_connection_response(char *data, struct MHD_Connection *connection)
{
  struct MHD_Response *response;
  enum MHD_Result ret;
  response = MHD_create_response_from_buffer(strlen(data), data, MHD_RESPMEM_MUST_COPY);
  if (response == NULL) {
    log_debug("NULL response error");
    // os_free(me);
    return MHD_NO;
  }

  ret = MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "application/json");
  if (ret == MHD_NO) {
    log_debug("MHD_add_response_header error");
    MHD_destroy_response(response);  
    // os_free(me);
    return MHD_NO;
  }
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

char* process_response_array(UT_array *cmd_arr)
{
  char **p = NULL;
  char *json_response = NULL;
  ssize_t len = 0; 
  while(p = (char**) utarray_next(cmd_arr, p)) {
    len += strlen(*p) + 2 + 1;
    if (json_response == NULL) {
      json_response = os_malloc(len);
      sprintf(json_response, "\"%s\"", *p);
    } else {
      json_response = os_realloc(json_response, len);
      strcat(json_response, ",");
      strcat(json_response, "\"");
      strcat(json_response, *p);
      strcat(json_response, "\"");
    }
  }

  return json_response;
}

static enum MHD_Result mhd_reply(void *cls, struct MHD_Connection *connection, const char *url,
  const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr)
{
  static int aptr;
  struct socket_address *sad = (struct socket_address *)cls;
  char *cmd, *args, *address = NULL, *socket_response, *json_response = NULL, *succ_response;
  char cmd_str[255], fail_response_buf[255];
  UT_array *cmd_arr;
  enum MHD_Result ret;

  (void) version;           /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  /* unexpected method */
  if (0 != strcmp (method, "GET")) {
    return MHD_NO;
  }

  if (&aptr != *ptr) {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }

  *ptr = NULL;                  /* reset when done */
  MHD_get_connection_values(connection, MHD_HEADER_KIND, (MHD_KeyValueIterator)&print_out_key, NULL);
  cmd = (char *) MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cmd");
  args = (char *) MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "args");

  log_info("URL --> %s %s", method, url);
  log_info("PARAMS --> cmd=%s args=%s", cmd, args);

  if (create_command_string(cmd, args, cmd_str, sad->delim) == NULL) {
    log_debug("create_command_string fail");
    sprintf(fail_response_buf, JSON_RESPONSE_FAIL);
    return create_connection_response(fail_response_buf, connection);
  }

  if (get_command_function(cmd) != NULL) {
    log_debug("Supervisor command=%s", cmd);
    address = sad->spath;
  } else {
    log_debug("AP command=%s", cmd);
    address = sad->apath;
  }

  if (send_ap_command(address, cmd_str, &socket_response) < 0) {
    log_debug("send_ap_command fail");
    sprintf(fail_response_buf, JSON_RESPONSE_FAIL);
    return create_connection_response(fail_response_buf, connection);
  }

  utarray_new(cmd_arr, &ut_str_icd);
  if (!process_domain_buffer(socket_response, strlen(socket_response), cmd_arr, '\n')) {
    log_debug("process_domain_buffer fail");
    sprintf(fail_response_buf, JSON_RESPONSE_FAIL);
    os_free(socket_response);
    utarray_free(cmd_arr);
    return create_connection_response(fail_response_buf, connection);
  }
  os_free(socket_response);

  json_response = process_response_array(cmd_arr);
  succ_response = os_malloc(strlen(JSON_RESPONSE_OK) + strlen(json_response) + strlen(cmd) + 1);
  sprintf(succ_response, JSON_RESPONSE_OK, cmd, json_response);
  os_free(json_response);
  utarray_free(cmd_arr);
  ret = create_connection_response(succ_response, connection);
  os_free(succ_response);

  return ret;
}

int main(int argc, char *argv[])
{
  struct MHD_Daemon *d;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  struct socket_address sad;
  int port = -1;
  char *key = NULL;
  char *cert = NULL;
  bool tls = false;
  int flags;
  char *db_path = NULL;
  char *passphrase = NULL;
  struct crypt_context *crypt_ctx;
  struct crypt_pair* get_pair;
  struct crypt_pair put_pair;
  char *keyhttps = "keyhttps";
  char *certhttps = "certhttps";

  os_memset(&sad, 0, sizeof(struct socket_address));

  process_app_options(argc, argv, sad.spath, sad.apath, &port, &sad.delim, &tls, &db_path, &passphrase, &verbosity); 

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

  if (port == -1) {
    log_cmdline_error("Unrecognized port value -%d\n", port);
    exit(EXIT_FAILURE); 
  }

  fprintf(stdout, "Starting server with:\n");
  fprintf(stdout, "Supervisor address --> %s\n", sad.apath);
  fprintf(stdout, "AP address --> %s\n", sad.spath);
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "Command delimiter --> %c\n", sad.delim);
  fprintf(stdout, "Using TLS --> %d\n", tls);
  fprintf(stdout, "Using crypt db path --> %s\n", db_path);

  if (tls) {
    if (crypto_generate_keycert_str(1024, &key, &cert) < 0) {
      fprintf(stderr, "crypto_generate_keycert_str failure\n");
      exit(EXIT_FAILURE);
    }

    if ((crypt_ctx = load_crypt_service(db_path, "microhttps", passphrase,
                                        (passphrase == NULL) ? 0 : os_strnlen_s(passphrase, MAX_USER_SECRET))) == NULL) {
      fprintf(stderr, "load_crypt_service fail\n");
      exit(EXIT_FAILURE);
    }

    get_pair = get_crypt_pair(crypt_ctx, keyhttps);

    if (get_pair == NULL) {
      fprintf(stderr, "get_crypt_pair failure\n");
      exit(EXIT_FAILURE);
    }

    if (!get_pair->value_size) {
      fprintf(stdout, "Inserting new key\n");
      put_pair.key = keyhttps;
      put_pair.value = key;
      put_pair.value_size = strlen(key) + 1;
      put_crypt_pair(crypt_ctx, &put_pair);
    } else {
      fprintf(stdout, "Retrieving existing key\n");
      os_free(key);
      key = os_zalloc(get_pair->value_size);
      os_memcpy(key, get_pair->value, get_pair->value_size);
    }
    free_crypt_pair(get_pair);

    get_pair = get_crypt_pair(crypt_ctx, certhttps);

    if (get_pair == NULL) {
      fprintf(stderr, "get_crypt_pair failure\n");
      exit(EXIT_FAILURE);
    }
    if (!get_pair->value_size) {
      fprintf(stdout, "Inserting new certificate\n");
      put_pair.key = certhttps;
      put_pair.value = cert;
      put_pair.value_size = strlen(cert) + 1;
      put_crypt_pair(crypt_ctx, &put_pair);
    } else {
      os_free(cert);
      fprintf(stdout, "Retrieving existing certificate\n");
      cert = os_zalloc(get_pair->value_size);
      os_memcpy(cert, get_pair->value, get_pair->value_size);
    }
    free_crypt_pair(get_pair);
    os_free(key);
    os_free(cert);
  }


  flags = MHD_USE_THREAD_PER_CONNECTION;
  flags = (tls) ? flags | MHD_USE_TLS : flags;

  fprintf(stdout, "Starting server...\n");
  d = MHD_start_daemon (flags, (uint16_t) port,
                        NULL, NULL, &mhd_reply, (void*)&sad,
                        MHD_OPTION_HTTPS_MEM_KEY, key,
                        MHD_OPTION_HTTPS_MEM_CERT, cert,
                        MHD_OPTION_END);

  if (d == NULL) {
    fprintf(stderr, "Error: Failed to start server\n");
    exit(EXIT_FAILURE);
  }

  (void) getc (stdin);
  MHD_stop_daemon (d);
  fprintf(stdout, "Server stopped\n");
  exit(EXIT_SUCCESS);
}