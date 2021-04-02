/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>
#include <sqlite3.h>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "sqlite_sync.grpc.pb.h"

#include "utils/os.h"
#include "utils/log.h"
#include "version.h"

#define OPT_STRING    ":f:p:dvh"
#define USAGE_STRING  "\t%s [-f path] [-p port] [-d] [-h] [-v]"

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
  fprintf(stdout, "\t-f folder\t\t Folder where to save teh databases\n");
  fprintf(stdout, "\t-p port\t\t Server port\n");
  fprintf(stdout, "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright Nquirignminds Ltd\n\n");
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

void process_app_options(int argc, char *argv[], int *port, char *path, uint8_t *verbosity)
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
      break;
    case 'p':
      if ((p = get_port(optarg)) < 0) {
        log_cmdline_error("Unrecognized port value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      *port = p;
      break;
    case 'f':
      memcpy(path, optarg, strlen(optarg) + 1);
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
  sqlite3 *db;
  if ((db = open_sqlite_db(db_path)) == NULL) {
    log_debug("open_sqlite_db fail");
    return -1;
  }

  sqlite3_close(db);
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

// Logic and data behind the server's behavior.
class SynchroniserServiceImpl final : public Synchroniser::Service {
 public:
  explicit SynchroniserServiceImpl(const std::string& path) : path_(path) {}
  
  Status RegisterDb(ServerContext* context, const RegisterDbRequest* request, RegisterDbReply* reply) override {
    if (request->name().length()) {
      const char *db_name = request->name().c_str();
      std::string db_path = GetDbPath((char *)db_name);

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
      std::string db_path = GetDbPath((char *)request->name().c_str());
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

int run_grpc_server(char *path, uint16_t port) {
  SynchroniserServiceImpl service(path);
  std::string server_address("0.0.0.0:");
  server_address += std::to_string(port);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;

  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

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

  os_memset(path, 0, MAX_OS_PATH_LEN);

  process_app_options(argc, argv, &port, path, &verbosity); 

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
  if (strlen(path)) {
    if (list_dir(path, NULL, NULL) == -1) {
      fprintf(stderr, "Can not read folder %s", path);
      exit(EXIT_FAILURE); 
    }
  } else {
    strcpy(path, "./");
  }

  fprintf(stdout, "Starting server with:\n");
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "DB save path --> %s\n", path);

  if (run_grpc_server(path, port) == -1) {
    fprintf(stderr, "run_grpc_server fail");
    exit(EXIT_FAILURE);
  } 

  return 0;
}