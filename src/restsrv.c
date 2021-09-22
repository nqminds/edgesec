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
#include "utils/base64.h"

#define SOCK_PACKET_SIZE 10

#define OPT_STRING    ":s:p:z:tdvh"
#define USAGE_STRING  "\t%s [-s address] [-p port] [-z delim] [-t] [-d] [-h] [-v]\n"

#define JSON_RESPONSE_OK    "{\"cmd\":\"%s\",\"response\":[%s]}"
#define JSON_RESPONSE_FAIL  "{\"error\":\"invalid get request\"}"
#define JSON_RESPONSE_HELP  "{\"commands\": [" \
                            "{\"PING_SUPERVISOR\":\"\"}," \
                            "{\"ACCEPT_MAC\":\"MAC VLANID\"}," \
                            "{\"DENY_MAC\":\"MAC\"}," \
                            "{\"ADD_NAT\":\"MAC\"}," \
                            "{\"REMOVE_NAT\":\"MAC\"}," \
                            "{\"ASSIGN_PSK\":\"MAC PASS\"}," \
                            "{\"GET_MAP\":\"MAC\"}," \
                            "{\"GET_ALL\":\"\"}," \
                            "{\"ADD_BRIDGE\":\"MAC MAC\"}," \
                            "{\"REMOVE_BRIDGE\":\"MAC MAC\"}," \
                            "{\"GET_BRIDGES\":\"\"}," \
                            "{\"REGISTER_TICKET\":\"MAC LABEL VLANID\"}," \
                            "{\"CLEAR_PSK\":\"MAC\"}," \
                            "{\"PUT_CRYPT\":\"KEYID BASE64VALUE\"}," \
                            "{\"GET_CRYPT\":\"KEYID\"}," \
                            "{\"GEN_RANDKEY\":\"KEYID SIZE\"}," \
                            "{\"GEN_PRIVKEY\":\"KEYID SIZE\"}," \
                            "{\"GEN_PUBKEY\":\"PUBKEYID PRIVKEYID\"}," \
                            "{\"GEN_CERT\":\"CERTID PRIVKEYID\"}," \
                            "{\"ENCRYPT_BLOB\":\"KEYID IVID BASE64BLOB\"}," \
                            "{\"DECRYPT_BLOB\":\"KEYID IVID BASE64BLOB\"}," \
                            "{\"SIGN_BLOB\":\"KEYID BASE64BLOB\"}" \
                            "], \"query\":\"/?cmd=name&args=arguments\"}"

#define CRYPT_KEY_ID        "restkey"
#define CRYPT_CERT_ID       "restcert"
#define GET_CRYPT_KEY_CMD   CMD_GET_CRYPT" "CRYPT_KEY_ID
#define GET_CRYPT_CERT_CMD  CMD_GET_CRYPT" "CRYPT_CERT_ID
#define GEN_PRIVKEY_CMD     CMD_GEN_PRIVKEY" "CRYPT_KEY_ID" 128"
#define GEN_CERT_CMD        CMD_GEN_CERT" "CRYPT_CERT_ID" "CRYPT_KEY_ID

static __thread char version_buf[10];

struct socket_address {
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

void process_app_options(int argc, char *argv[], char *spath,
                         int *port, char *delim, bool *tls,
                        uint8_t *verbosity)
{
  int opt;
  int p;
  *tls = false;
  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
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
  (void) cls;
  (void) kind;
  log_info("HEADER --> key=%s value=%s", key, value);
  return MHD_YES;
}

char* create_command_string(char *cmd, char *args, char delim)
{
  char *cmd_upper, *cmd_str = NULL;
  if (cmd == NULL)
    return NULL;

  if ((cmd_upper = os_strdup(cmd)) == NULL) {
    log_err("os_strdup");
    return NULL;
  }

  upper_string(cmd_upper);

  if (args ==  NULL) {
    if ((cmd_str = os_malloc(strlen(cmd_upper) + 1)) == NULL) {
      log_err("os_malloc");
      os_free(cmd_upper);
      return NULL;    
    }
    sprintf(cmd_str, "%s", cmd_upper);
  } else {
    if ((cmd_str = os_malloc(strlen(cmd_upper) + strlen(args) + 2)) == NULL) {
      log_err("os_malloc");
      os_free(cmd_upper);
      return NULL;    
    }
    sprintf(cmd_str, "%s%c%s", cmd_upper, delim, args);
  }
  os_free(cmd_upper);

  return cmd_str;
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
  while((p = (char**) utarray_next(cmd_arr, p)) != NULL) {
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
  char *cmd, *args, *socket_response, *json_response = NULL, *succ_response;
  char *cmd_str, *response_buf;
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

  if (cmd == NULL && args == NULL) {
    if ((response_buf = os_malloc(strlen(JSON_RESPONSE_HELP) + 1)) == NULL) {
      log_err("os_malloc");
      return MHD_NO;
    }

    sprintf(response_buf, JSON_RESPONSE_HELP);
    ret = create_connection_response(response_buf, connection);
    os_free(response_buf);
    return ret;
  }

  if ((cmd_str = create_command_string(cmd, args, sad->delim)) == NULL) {
    log_debug("create_command_string fail");
    if ((response_buf = os_malloc(strlen(JSON_RESPONSE_FAIL) + 1)) == NULL) {
      log_err("os_malloc");
      return MHD_NO;
    }

    sprintf(response_buf, JSON_RESPONSE_FAIL);
    ret = create_connection_response(response_buf, connection);
    os_free(response_buf);
    return ret;
  }

  if (writeread_domain_data_str(sad->spath, cmd_str, &socket_response) < 0) {
    log_debug("writeread_domain_data_str fail");
    if ((response_buf = os_malloc(strlen(JSON_RESPONSE_FAIL) + 1)) == NULL) {
      log_err("os_malloc");
      os_free(cmd_str);
      return MHD_NO;
    }

    sprintf(response_buf, JSON_RESPONSE_FAIL);
    ret =  create_connection_response(response_buf, connection);

    os_free(response_buf);
    os_free(cmd_str);
    return ret;
  }
  os_free(cmd_str);

  utarray_new(cmd_arr, &ut_str_icd);
  if (!process_domain_buffer(socket_response, strlen(socket_response), cmd_arr, '\n')) {
    log_debug("process_domain_buffer fail");
    if ((response_buf = os_malloc(strlen(JSON_RESPONSE_FAIL) + 1)) == NULL) {
      log_err("os_malloc");
      os_free(socket_response);
      utarray_free(cmd_arr);
      return MHD_NO;
    }

    sprintf(response_buf, JSON_RESPONSE_FAIL);
    ret = create_connection_response(response_buf, connection);
    os_free(socket_response);
    utarray_free(cmd_arr);
    os_free(response_buf);
    return ret;
  }
  os_free(socket_response);

  if ((json_response = process_response_array(cmd_arr)) == NULL) {
    json_response = os_strdup("");
  }

  if ((succ_response = os_malloc(strlen(JSON_RESPONSE_OK) + strlen(json_response) + strlen(cmd) + 1)) == NULL) {
    log_err("os_malloc");
    os_free(json_response);
    utarray_free(cmd_arr);
    return MHD_NO;
  }

  sprintf(succ_response, JSON_RESPONSE_OK, cmd, json_response);
  ret = create_connection_response(succ_response, connection);

  os_free(succ_response);
  os_free(json_response);
  utarray_free(cmd_arr);

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
  char *reply = NULL;
  uint8_t *base64_buf = NULL;
  size_t base64_buf_len;

  os_memset(&sad, 0, sizeof(struct socket_address));

  process_app_options(argc, argv, sad.spath, &port, &sad.delim, &tls, &verbosity); 

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
  fprintf(stdout, "Supervisor address --> %s\n", sad.spath);
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "Command delimiter --> %c\n", sad.delim);
  fprintf(stdout, "Using TLS --> %d\n", tls);

  if (tls) {
    if (writeread_domain_data_str(sad.spath, GET_CRYPT_KEY_CMD, &reply) < 0) {
      fprintf(stderr, "writeread_domain_data_str fail");
      exit(EXIT_FAILURE);
    }

    if (strcmp(reply, FAIL_REPLY) == 0) {
      os_free(reply);
      fprintf(stdout, "Generating new private key\n");
      if (writeread_domain_data_str(sad.spath, GEN_PRIVKEY_CMD, &reply) < 0) {
        fprintf(stderr, "writeread_domain_data_str fail");
        exit(EXIT_FAILURE);
      }
      if (strcmp(reply, FAIL_REPLY) == 0) {
        fprintf(stderr, "writeread_domain_data_str fail");
        exit(EXIT_FAILURE);
      }
      os_free(reply);

      fprintf(stdout, "Generating new certificate key\n");
      if (writeread_domain_data_str(sad.spath, GEN_CERT_CMD, &reply) < 0) {
        fprintf(stderr, "writeread_domain_data_str fail");
        exit(EXIT_FAILURE);
      }
      if (strcmp(reply, FAIL_REPLY) == 0) {
        fprintf(stderr, "writeread_domain_data_str fail");
        exit(EXIT_FAILURE);
      }
    }

    os_free(reply);
    fprintf(stdout, "Loading existing private key\n");
    if (writeread_domain_data_str(sad.spath, GET_CRYPT_KEY_CMD, &reply) < 0) {
      fprintf(stderr, "writeread_domain_data_str fail");
      exit(EXIT_FAILURE);
    }

    if (strcmp(reply, FAIL_REPLY) == 0) {
      fprintf(stderr, "writeread_domain_data_str fail");
      exit(EXIT_FAILURE);
    }

    if ((base64_buf = (uint8_t *) base64_decode((unsigned char *) reply, strlen(reply), &base64_buf_len)) == NULL) {
      fprintf(stderr, "base64_decode fail");
      exit(EXIT_FAILURE);
    }
    if ((key = os_zalloc(base64_buf_len + 1)) == NULL) {
      fprintf(stderr, "os_zalloc fail");
      exit(EXIT_FAILURE);
    }
    os_memcpy(key, base64_buf, base64_buf_len);
    os_free(base64_buf);
    os_free(reply);

    fprintf(stdout, "Loading existing certificate\n");
    if (writeread_domain_data_str(sad.spath, GET_CRYPT_CERT_CMD, &reply) < 0) {
      fprintf(stderr, "writeread_domain_data_str fail");
      exit(EXIT_FAILURE);
    }

    if (strcmp(reply, FAIL_REPLY) == 0) {
      fprintf(stderr, "writeread_domain_data_str fail");
      exit(EXIT_FAILURE);
    }

    if ((base64_buf = (uint8_t *) base64_decode((unsigned char *) reply, strlen(reply), &base64_buf_len)) == NULL) {
      fprintf(stderr, "base64_decode fail");
      exit(EXIT_FAILURE);
    }
    if ((cert = os_zalloc(base64_buf_len + 1)) == NULL) {
      fprintf(stderr, "os_zalloc fail");
      exit(EXIT_FAILURE);
    }
    os_memcpy(cert, base64_buf, base64_buf_len);
    os_free(base64_buf);
    os_free(reply);
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

  if (key != NULL) os_free(key);
  if (cert != NULL) os_free(cert);

  MHD_stop_daemon (d);
  fprintf(stdout, "Server stopped\n");
  exit(EXIT_SUCCESS);
}