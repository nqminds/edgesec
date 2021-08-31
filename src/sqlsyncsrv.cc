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
 * @file sqlsyncsrv.cc 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the sync server.
 */

#include <sys/stat.h>
#include <iostream>
#include <memory>
#include <string>
#include <sqlite3.h>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "sqlite_sync.grpc.pb.h"

#include "capture/sqlite_header_writer.h"
#include "crypt/crypt_service.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/log.h"
#include "utils/cryptou.h"
#include "config.h"
#include "version.h"

#define OPT_STRING    ":f:p:c:u:n:dvh"
#define USAGE_STRING  "\t%s [-f path] [-p port] [-c path] [-u passphrase] [-n hostname] [-d] [-h] [-v]"

#define DEFAULT_DB_NAME "sync.sqlite"
#define KEY_ID    "syncgrpc"
#define KEY_NAME  "keysyncgrpc"
#define CERT_NAME "certsyncgrpc"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using sqlite_sync::Synchroniser;
using sqlite_sync::RegisterDbRequest;
using sqlite_sync::RegisterDbReply;
using sqlite_sync::SyncDbStatementRequest;
using sqlite_sync::SyncDbStatementReply;

static __thread char version_buf[10];

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
  fprintf(stdout, "sqlsyncsrv app version %s\n",
    get_static_version_string(SQLSYNCSRV_VERSION_MAJOR, SQLSYNCSRV_VERSION_MINOR,
    SQLSYNCSRV_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-f folder\t\t Folder where to save the databases\n");
  fprintf(stdout, "\t-p port\t\t Server port\n");
  fprintf(stdout, "\t-c path\t\t The crypt db path\n");
  fprintf(stdout, "\t-u passphrase\t\t The user passphrase for TLS connection\n");
  fprintf(stdout, "\t-n hostname\t\t The hostname for certificate\n");
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

void process_app_options(int argc, char *argv[], int *port, char *path,
                         char *crypt_path, char *passphrase,
                         char *hostname, uint8_t *verbosity)
{
  int opt;
  int p;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
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
    case 'p':
      if ((p = get_port(optarg)) < 0) {
        log_cmdline_error("Unrecognized port value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      *port = p;
      break;
    case 'f':
      os_strlcpy(path, optarg, MAX_OS_PATH_LEN);
      break;
    case 'c':
      os_strlcpy(crypt_path, optarg, MAX_OS_PATH_LEN);
      break;
    case 'u':
      os_strlcpy(passphrase, optarg, MAX_USER_SECRET);
      break;
    case 'n':
      os_strlcpy(hostname, optarg, MAX_WEB_PATH_LEN);
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

sqlite3* open_sqlite_db(char *db_path)
{
  sqlite3 *db;
  if (sqlite3_open(db_path, &db) != SQLITE_OK) {     
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return NULL;
  }

  return db;
}

int create_sqlite_db(char *db_path)
{
  struct sqlite_header_context *ctx = NULL;
  if (open_sqlite_header_db(db_path, NULL, NULL, &ctx) < 0) {
    log_debug("open_sqlite_header_db fail");
    return -1;
  }
  free_sqlite_header_db(ctx);

  // sqlite3 *db;
  // if ((db = open_sqlite_db(db_path)) == NULL) {
  //   log_debug("open_sqlite_db fail");
  //   return -1;
  // }

  // sqlite3_close(db);
  return 0;
}

int execute_sqlite_statement(char *db_path, char *statement)
{
  sqlite3 *db;
  char *err = NULL;
  if ((db = open_sqlite_db(db_path)) == NULL) {
    log_debug("open_sqlite_db fail");
    return -1;
  }

  if (sqlite3_exec(db, statement, NULL, NULL, &err) != SQLITE_OK) {
    log_debug("sqlite3_exec fail %s", err);
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }

  sqlite3_close(db);

  return 0;
}

std::string get_db_path(std::string path, char *db_name)
{
  std::string db_path;
  char *dpath = construct_path((char *) path.c_str(), db_name);
  db_path = dpath;
  os_free(dpath);
  return db_path;
}

// Logic and data behind the server's behavior.
class SynchroniserServiceImpl final : public Synchroniser::Service {
 public:
  explicit SynchroniserServiceImpl(const std::string& path) : path_(path) {}
  
  Status RegisterDb(ServerContext* context, const RegisterDbRequest* request, RegisterDbReply* reply) override {
    if (request->name().length()) {
      const char *db_name = request->name().c_str();
      std::string db_path = get_db_path(path_, (char *)db_name);

      if (create_sqlite_db((char *)db_path.c_str()) == -1) {
        log_debug("Could not registered db=%s", db_name);
        reply->set_status(0);
      } else {
        log_debug("Registered db=%s at=%s", db_name, (char *)db_path.c_str());
        reply->set_status(1);
      }
    } else {
      log_debug("db name empty");
      reply->set_status(0);
    }
    return Status::OK;
  }

  Status SyncDbStatement(ServerContext* context, const SyncDbStatementRequest* request, SyncDbStatementReply* reply) override {
    if (request->name().length() && request->statement().length()) {
      std::string db_path = (request->default_db()) ?
                            get_db_path(path_, (char *)DEFAULT_DB_NAME) :
                            get_db_path(path_, (char *)request->name().c_str());
      if (execute_sqlite_statement((char *)db_path.c_str(), (char *)request->statement().c_str()) == -1) {
        log_debug("execute_sqlite_statement fail");
        reply->set_status(0);
      } else {
        log_debug("Executed Statement with length=%d", request->statement().length());
        reply->set_status(1);
      }
    } else {
      log_debug("name or statement are empty");
      reply->set_status(0);
    }

    return Status::OK;
  }

  std::string GetDbPath(char *db_name) {
    std::string db_path;
    char *dpath = construct_path((char *) path_.c_str(), db_name);
    db_path = dpath;
    os_free(dpath);
    return db_path;
  }

  private:
    std::string path_;
};

int run_grpc_server(char *path, uint16_t port, char *key, char *cert) {
  SynchroniserServiceImpl service(path);
  std::string server_address("0.0.0.0:");
  server_address += std::to_string(port);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;

  if (key == NULL && cert == NULL) {
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  } else {
    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {key, cert};
    grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
    ssl_opts.pem_key_cert_pairs.push_back(pkcp);
    std::shared_ptr<grpc::ServerCredentials> creds = grpc::SslServerCredentials(ssl_opts);
    builder.AddListeningPort(server_address, creds);
  }

  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  fprintf(stdout, "Server listening on %s\n", server_address.c_str());

  server->Wait();

  return 0;
}

int main(int argc, char** argv) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  int port = -1;
  char path[MAX_OS_PATH_LEN];
  char crypt_path[MAX_OS_PATH_LEN];
  char passphrase[MAX_USER_SECRET];
  char hostname[MAX_WEB_PATH_LEN];
  struct crypt_context *crypt_ctx;
  struct crypt_pair* get_pair;
  struct crypt_pair put_pair;
  char *key = NULL;
  char *cert = NULL;

  os_memset(passphrase, 0, MAX_USER_SECRET);
  os_memset(path, 0, MAX_OS_PATH_LEN);

  process_app_options(argc, argv, &port, path, crypt_path,
                      passphrase, hostname, &verbosity); 

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

  if (port <=0 || port > 65535) {
    log_cmdline_error("Unrecognized port value -%d\n", port);
    exit(EXIT_FAILURE);
  }

  // Check if directory can be read
  if (os_strnlen_s(path, MAX_OS_PATH_LEN)) {
    if (create_dir(path, S_IRWXU | S_IRWXG) < 0) {
      fprintf(stderr, "create_dir fail");
      exit(EXIT_FAILURE);
    }
  } else {
    strcpy(path, "./");
  }

  std::string db_path = get_db_path(path, (char *)DEFAULT_DB_NAME);
  if (create_sqlite_db((char *)db_path.c_str()) == -1) {
    fprintf(stderr, "Could not create db=%s", DEFAULT_DB_NAME);
    exit(EXIT_FAILURE);
  }

  fprintf(stdout, "Starting server with:\n");
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "Default DB save path --> %s\n", db_path.c_str());
  fprintf(stdout, "Crypt DB path --> %s\n", crypt_path);
  fprintf(stdout, "Hostname --> %s\n", hostname);

  if (strlen(passphrase)) {
    fprintf(stdout, "Creating/loading certificates...\n");
    if (crypto_generate_keycert_str(1024, &key, &cert) < 0) {
      fprintf(stderr, "crypto_generate_keycert_str failure\n");
      exit(EXIT_FAILURE);
    }

    if ((crypt_ctx = load_crypt_service(crypt_path, (char *)KEY_ID, (uint8_t *)passphrase,
                                        (passphrase == NULL) ? 0 : os_strnlen_s(passphrase, MAX_USER_SECRET))) == NULL) {
      fprintf(stderr, "load_crypt_service fail\n");
      exit(EXIT_FAILURE);
    }

    get_pair = get_crypt_pair(crypt_ctx, (char *)KEY_NAME);

    if (get_pair == NULL) {
      fprintf(stderr, "get_crypt_pair failure\n");
      exit(EXIT_FAILURE);
    }

    if (!get_pair->value_size) {
      fprintf(stdout, "Inserting new key\n");
      put_pair.key = (char *)KEY_NAME;
      put_pair.value = (uint8_t *)key;
      put_pair.value_size = strlen(key) + 1;
      put_crypt_pair(crypt_ctx, &put_pair);
    } else {
      fprintf(stdout, "Retrieving existing key\n");
      os_free(key);
      key = (char *)os_zalloc(get_pair->value_size);
      os_memcpy(key, get_pair->value, get_pair->value_size);
    }
    free_crypt_pair(get_pair);

    get_pair = get_crypt_pair(crypt_ctx, (char *)CERT_NAME);

    if (get_pair == NULL) {
      fprintf(stderr, "get_crypt_pair failure\n");
      exit(EXIT_FAILURE);
    }

    if (!get_pair->value_size) {
      fprintf(stdout, "Inserting new certificate\n");
      put_pair.key = (char *)CERT_NAME;
      put_pair.value = (uint8_t *)cert;
      put_pair.value_size = strlen(cert) + 1;
      put_crypt_pair(crypt_ctx, &put_pair);
    } else {
      os_free(cert);
      fprintf(stdout, "Retrieving existing certificate\n");
      cert = (char *)os_zalloc(get_pair->value_size);
      os_memcpy(cert, get_pair->value, get_pair->value_size);
    }
    free_crypt_pair(get_pair);
    os_free(key);
    os_free(cert);
  }

  if (run_grpc_server(path, port, key, cert) == -1) {
    fprintf(stderr, "run_grpc_server fail");
    exit(EXIT_FAILURE);
  } 

  return 0;
}