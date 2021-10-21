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
 * @file revclient.cc 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the reverse client.
 */

#include <sys/types.h>
#include <dirent.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <sqlite3.h>

#include <grpcpp/grpcpp.h>


#include "reverse_access.grpc.pb.h"

#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/log.h"
#include "utils/base64.h"
#include "version.h"
#include "revcmd.h"

#define OPT_STRING    ":f:a:p:c:dvh"
#define USAGE_STRING  "\t%s [-f path] [-a address] [-p port] [-c path] [-d] [-h] [-v]"

#define FAIL_REPLY  "FAIL"
#define OK_REPLY   "OK"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;
using reverse_access::Reverser;
using reverse_access::CommandRequest;
using reverse_access::CommandReply;
using reverse_access::ResourceRequest;
using reverse_access::ResourceReply;

static __thread char version_buf[10];

const std::string METADATA_KEY = "client-id";

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
  fprintf(stdout, "revclient app version %s\n",
    get_static_version_string(REVCLIENT_VERSION_MAJOR, REVCLIENT_VERSION_MINOR,
    REVCLIENT_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-f folder\t Folder to sync\n");
  fprintf(stdout, "\t-a address\t Server address\n");
  fprintf(stdout, "\t-p port\t\t Server port\n");
  fprintf(stdout, "\t-c path\t\t The certificate authority path\n");
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
                        char *address, char *ca_path,  uint8_t *verbosity)
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
    case 'a':
      os_strlcpy(address, optarg, MAX_WEB_PATH_LEN);
      break;
    case 'p':
      if ((p = get_port(optarg)) < 0) {
        log_cmdline_error("Unrecognized port value -%s\n", optarg);
        exit(EXIT_FAILURE);
      }
      *port = p;
      break;
    case 'c':
      os_strlcpy(ca_path, optarg, MAX_OS_PATH_LEN);
      break;
    case 'f':
      os_strlcpy(path, optarg, MAX_OS_PATH_LEN);
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

int get_folder_list(std::string path, std::vector<std::string> &folder_list) {
  DIR *dirp;
  struct dirent *dp;

  /* Open the directory - on failure print an error and return */
  errno = 0;
  dirp = opendir(path.c_str());
  if (dirp == NULL) {
    log_err("opendir");
    return -1;
  }

  /* Look at each of the entries in this directory */
  for (;;) {
    errno = 0;              /* To distinguish error from end-of-directory */
    dp = readdir(dirp);

    if (dp == NULL)
      break;

    /* Skip . and .. */
    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
      continue;

    folder_list.push_back(dp->d_name);
  }

  if (errno != 0) {
    log_err("readdir");
    return -1;
  }

  if (closedir(dirp) == -1) {
    log_err("closedir");
    return -1;
  }

  return 0;
}

std::string accumulate_string(std::vector<std::string> &string_list)
{
  std::string acc;
  for (const auto &el : string_list) acc += el + "\n";
  return acc;
}

ssize_t read_file(const char *name, char **encoded)
{
  ssize_t file_size = 0, read_size;
  unsigned char *file_data;
  size_t out_len;
  *encoded = NULL;

  if (name == NULL) {
    return -1;
  }

  FILE *fp = fopen(name, "r");

  log_trace("Opening %s", name);

  if (fp == NULL) {
    log_err("fopen");
    return -1;
  }

  if (fseek(fp, 0 , SEEK_END) < 0) {
    log_err("fseek");
    fclose(fp);
    return -1; 
  }

  if ((file_size = ftell(fp)) == -1L) {
    log_err("ftell");
    fclose(fp);
    return -1;
  }

  rewind(fp);

  if ((file_data = (unsigned char*) os_malloc(file_size)) == NULL) {
    fclose(fp);
    return -1; 
  }

  read_size = fread(file_data, 1, file_size, fp);

  if (read_size != file_size) {
    log_trace("fread fail");
    os_free(file_data);
    fclose(fp);
    return -1;
  }

  fclose(fp);

  if ((*encoded = (char *) base64_encode(file_data, file_size, &out_len)) == NULL) {
    log_trace("base64_encode");
    os_free(file_data);
    return -1;
  }

  os_free(file_data);

  return out_len;
}

int sqlite_exec_callback(void* ptr ,int argc, char **argv, char **colname)
{
  char **out = (char **)ptr, *str;
  size_t out_size;
  std::string row, column;

  if (*out == NULL) {
    for (int i = 0; i < argc; i++) {
      std::string val = colname[i];
      if (i == argc - 1)
        column += val + '\n';
      else column += val + ',';
    }
    str = (char *)column.c_str();
    if ((*out = (char *)os_zalloc(strlen(str) + 1)) == NULL) {
      log_err("os_zalloc");
      return -1;
    }
    strcpy(*out, column.c_str());
  }

  for (int i = 0; i < argc; i++) {
    std::string val = (argv[i] ? argv[i] : "NULL");
    if (i == argc - 1)
      row += val + '\n';
    else row += val + ',';
  }
  str = (char *)row.c_str();
  if (*out != NULL && strlen(str)) {
    out_size = strlen(*out) + strlen(str) + 1;
    if ((*out = (char *)os_realloc(*out, out_size)) == NULL) {
      log_err("os_realloc");
      return -1;
    }
    strcat(*out, str);
  }
  return 0;
}

int process_sql_execute(std::string db_path, std::string args, std::string &out)
{
  int rc;
  sqlite3 *db = NULL;
  char *file_path, *decoded_statement, *err = NULL;
  std::vector<std::string> arg_list;
  char *sqlite_out = NULL;
  split_string(arg_list, args, COMMAND_SEPARATOR);

  if (arg_list.size() < 2) {
    log_trace("Not enough arguments");
    return -1;
  }

  std::string filename = arg_list.at(0);
  std::string sql_statement = arg_list.at(1);
  size_t statement_len = 0;
  file_path = construct_path((char *)db_path.c_str(), (char *)filename.c_str());
  if (file_path == NULL) {
    log_trace("construct_path fail");
    return -1;
  }

  log_trace("Opening sqlite db=%s", file_path);
  if (sqlite3_open(file_path, &db) != SQLITE_OK) {     
    log_debug("Cannot open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    os_free(file_path);
    return -1;
  }

  os_free(file_path);
  unsigned char *ptr = (unsigned char *)sql_statement.c_str();
  if ((decoded_statement = (char *)base64_url_decode(ptr, strlen((char *)ptr), &statement_len)) == NULL) {
    log_trace("base64_url_decode fail");
    sqlite3_close(db);
    return -1;
  }
  log_trace("Executing statement %s", decoded_statement);

  if (sqlite3_exec(db, decoded_statement, sqlite_exec_callback, &sqlite_out, &err) != SQLITE_OK) {
    log_trace("sqlite3_exec error %s", err);
    os_free(decoded_statement);
    if (sqlite_out != NULL) os_free(sqlite_out);
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }

  if (sqlite_out != NULL) {
    out = std::string(sqlite_out);
    os_free(sqlite_out);
  }

  os_free(decoded_statement);
  sqlite3_close(db);
  return 0;
}

class ReverseClient {
 public:
  ReverseClient(std::shared_ptr<Channel> channel, std::string path, std::string id, std::string hostname)
      : stub_(Reverser::NewStub(channel)), path_(path), id_(id), hostname_(hostname) {}

  int SendStringResource(std::string command_id, const uint32_t command, const std::string& data) {
    ResourceRequest request;
    ResourceReply reply;
    ClientContext context;

    context.AddMetadata(METADATA_KEY, id_);
    request.set_command(command);
    request.set_id(command_id);
    request.set_data(data);
    Status status = stub_->SendResource(&context, request, &reply);

    if (status.ok()) {
      return 0;
    } else {
      log_debug("Error code=%d, %s", (int)status.error_code(), status.error_message().c_str());
      return -1;
    }
  }

  int SubscribeCommand(void) {
    CommandRequest request;
    ClientContext context;

    request.set_hostname(hostname_);
    context.AddMetadata(METADATA_KEY, id_);

    std::unique_ptr<ClientReader<CommandReply>> reader(stub_->SubscribeCommand(&context, request));

    std::thread reader_thread([&]() {
      CommandReply reply;
      log_trace("Subscribing to commands.");
      while (reader->Read(&reply)) {
        // Process the reply
        // List command
        std::vector<std::string> folder_list;
        char *file_path;
        char *file_data = NULL;
        ssize_t file_size;
        uint32_t cmd = reply.command();
        std::string args = reply.args();
        std::string reply_id = reply.id();
        std::string exec_out;

        log_trace("Processing command=%d with id=%s", cmd, reply_id.c_str());
        switch(cmd) {
          case REVERSE_CMD_LIST:
            if (get_folder_list(path_, folder_list) != -1) {
              std::string acc = accumulate_string(folder_list);
              SendStringResource(reply_id, REVERSE_CMD_LIST, acc);
            } else SendStringResource(reply_id, REVERSE_CMD_ERROR, "");
            break;
          case REVERSE_CMD_GET:
            log_trace("Received args=%s", args.c_str());
            file_path = construct_path((char *)path_.c_str(), (char *)args.c_str());
            if (file_path == NULL) {
              log_trace("construct_path fail");
              SendStringResource(reply_id, REVERSE_CMD_ERROR, "");
            } else {
              if ((file_size = read_file(rtrim(file_path, NULL), &file_data)) > -1) {
                SendStringResource(reply_id, REVERSE_CMD_GET, file_data);
                os_free(file_data);
              } else {
                SendStringResource(reply_id, REVERSE_CMD_ERROR, "");
              }
              os_free(file_path);
            }
            break;
          case REVERSE_CMD_SQL_EXECUTE:
            log_trace("Received args=%s", args.c_str());
            if (process_sql_execute(path_, args, exec_out) < 0) {
              log_trace("process_sql_execute fail");
              SendStringResource(reply_id, REVERSE_CMD_ERROR, "");
            } else {
              SendStringResource(reply_id, REVERSE_CMD_SQL_EXECUTE, exec_out);
            }
            break;
          case REVERSE_CMD_CLIENT_EXIT:
            SendStringResource(reply_id, REVERSE_CMD_CLIENT_EXIT, "");
            log_trace("Exiting client");
            exit(0);
          default:
            log_trace("Unknown command");
        }
      }
    });

    reader_thread.join();
    Status status = reader->Finish();

    if (!status.ok()) {
      return -1;
    }

    return 0;
  }

 private:

  std::unique_ptr<Reverser::Stub> stub_;
  std::string path_;
  std::string id_;
  std::string hostname_;
};

int run_grpc_client(char *path, int port, char *address, char *ca)
{
  char grpc_address[MAX_WEB_PATH_LEN];
  char rid[MAX_RANDOM_UUID_LEN];
  char hostname[OS_HOST_NAME_MAX];
  generate_radom_uuid(rid);
  std::string id(rid);
  snprintf(grpc_address, MAX_WEB_PATH_LEN, "%s:%d", address, port);

  if (get_hostname(hostname) < 0) {
    log_debug("get_hostname fail");
    return -1;
  }

  fprintf(stdout, "Connecting to %s... with id=%s and hostname=%s\n", grpc_address, rid, hostname);

  std::shared_ptr<grpc::ChannelCredentials> creds;
  if (ca != NULL) {
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca;
    creds = grpc::SslCredentials(ssl_opts);
    fprintf(stdout, "Configured TLS connection\n");
  } else {
    creds = grpc::InsecureChannelCredentials();
    fprintf(stdout, "Configured unsecured connection\n");
  }

  ReverseClient reverser(grpc::CreateChannel(grpc_address, creds), path, id, hostname); 
  while (reverser.SubscribeCommand() < 0) {
    log_debug("grpc SubscribeCommand failed");
    sleep(2);
  }

  return 0;
}

int main(int argc, char** argv) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  int port = -1;
  char path[MAX_OS_PATH_LEN];
  char address[MAX_WEB_PATH_LEN];
  char ca_path[MAX_OS_PATH_LEN];
  char *ca = NULL;  

  os_memset(ca_path, 0, MAX_OS_PATH_LEN);
  os_memset(path, 0, MAX_OS_PATH_LEN);

  process_app_options(argc, argv, &port, path, address, ca_path, &verbosity); 

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
    if (list_dir(path, NULL, NULL) == -1) {
      fprintf(stderr, "Can not read folder %s", path);
      exit(EXIT_FAILURE); 
    }
  } else {
    strcpy(path, "./");
  }

  fprintf(stdout, "Starting reverse client with:\n");
  fprintf(stdout, "Address --> %s\n", address);
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "DB save path --> %s\n", path);
  fprintf(stdout, "Cert authority path --> %s\n", ca_path);

  if (strlen(ca_path)) {
    if (read_file_string(ca_path, &ca) < 0) {
      fprintf(stderr, "read_file_string fail\n");
      exit(1);
    }
  }

  if (run_grpc_client(path, port, address, ca) == -1) {
    fprintf(stderr, "run_grpc_server fail\n");
    exit(EXIT_FAILURE);
  } 

  if (ca != NULL)
    os_free(ca);

  return 0;
}