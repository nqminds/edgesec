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

#include <grpcpp/grpcpp.h>
#include <thread>

#include "reverse_access.grpc.pb.h"

#include "utils/os.h"
#include "utils/log.h"
#include "version.h"
#include "revcmd.h"

#define OPT_STRING    ":f:a:p:dvh"
#define USAGE_STRING  "\t%s [-f path] [-a address] [-p port] [-d] [-h] [-v]"

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

void process_app_options(int argc, char *argv[], int *port,
                        char *path, char *address, uint8_t *verbosity)
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
      strncpy(address, optarg, MAX_WEB_PATH_LEN);
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

ssize_t read_file(const char *name, char **data)
{
  ssize_t file_size = 0;
  *data = NULL;

  if (name == NULL)
    return 0;

  FILE *fp = fopen(name, "r");
  if (fp == NULL) {
    log_err("fopen");
    return 0;
  }

  fseek(fp, 0 , SEEK_END);
  file_size = ftell(fp);
  rewind(fp);
  *data = (char*) os_malloc(file_size);

  return fread(*data, 1, file_size, fp);
  fclose(fp);
}

class ReverseClient {
 public:
  ReverseClient(std::shared_ptr<Channel> channel, std::string path, std::string id)
      : stub_(Reverser::NewStub(channel)), path_(path), id_(id) {}

  int SendStringResource(const uint32_t command, const std::string& data) {
    ResourceRequest request;
    ResourceReply reply;
    ClientContext context;

    request.set_command(command);
    request.set_id(id_);
    request.set_data(data);
    Status status = stub_->SendResource(&context, request, &reply);

    if (status.ok()) {
      return 0;
    } else {
      log_debug("Error code=%d, %s", (int)status.error_code(), status.error_message().c_str());
      return -1;
    }
  }

  int SendBinaryResource(const uint32_t command, const char *data, ssize_t len) {
    ResourceRequest request;
    ResourceReply reply;
    ClientContext context;

    request.set_command(command);
    request.set_id(id_);
    request.set_data(data, len);
    Status status = stub_->SendResource(&context, request, &reply);

    if (status.ok()) {
      return 0;
    } else {
      log_debug("Error code=%d, %s", (int)status.error_code(), status.error_message().c_str());
      return -1;
    }
  }

  int SubscribeCommand(const std::string& id) {
    CommandRequest request;
    ClientContext context;

    request.set_id(id);

    std::unique_ptr<ClientReader<CommandReply>> reader(stub_->SubscribeCommand(&context, request));

    std::thread reader_thread([&]() {
      CommandReply reply;
      while (reader->Read(&reply)) {
        // Process the reply
        // List command
        std::vector<std::string> folder_list;
        char *file_path;
        char *file_data = NULL;
        ssize_t file_size;
        log_trace("Processing command=%d with id=%s", reply.command(), reply.id().c_str());
        switch(reply.command()) {
          case REVERSE_CMD_LIST:
            if (get_folder_list(path_, folder_list) != -1) {
              std::string acc = accumulate_string(folder_list);
              SendStringResource(REVERSE_CMD_LIST, acc);
            } else SendStringResource(0, "\n");
            break;
          case REVERSE_CMD_GET:
            log_trace("Received args=%s", reply.args().c_str());
            file_path = construct_path((char *)path_.c_str(), (char *)reply.args().c_str());
            if (file_path == NULL) {
              log_trace("construct_path fail");
              SendStringResource(REVERSE_CMD_GET, "\n");
            } else {
              file_size = read_file(file_path, &file_data);
              os_free(file_path);
              if (file_data != NULL) {
                SendBinaryResource(REVERSE_CMD_GET, file_data, file_size);
                os_free(file_data);
              } else
                SendStringResource(REVERSE_CMD_GET, "\n");
            }
            break;
          default:
            log_trace("Unknown command");
        }
      }
    });

    reader_thread.join();
    Status status = reader->Finish();

    if (!status.ok())
      return -1;

    return 0;
  }

 private:

  std::unique_ptr<Reverser::Stub> stub_;
  std::string path_;
  std::string id_;

};

int run_grpc_client(char *path, int port, char *address)
{
  char grpc_address[MAX_WEB_PATH_LEN];
  char rid[MAX_RANDOM_UUID_LEN];
  generate_radom_uuid(rid);
  std::string id(rid);
  snprintf(grpc_address, MAX_WEB_PATH_LEN, "%s:%d", address, port);

  log_info("Connecting to %s... with id=%s", grpc_address, rid);
  ReverseClient reverser(grpc::CreateChannel(grpc_address, grpc::InsecureChannelCredentials()), path, id); 
  if (reverser.SubscribeCommand(id) < 0) {
    log_debug("grpc SubscribeCommand failed");
    return -1;
  }

  return 0;
}

int main(int argc, char** argv) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  int port = -1;
  char path[MAX_OS_PATH_LEN];
  char address[MAX_WEB_PATH_LEN];

  os_memset(path, 0, MAX_OS_PATH_LEN);

  process_app_options(argc, argv, &port, path, address, &verbosity); 

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

  fprintf(stdout, "Starting reverse client with:\n");
  fprintf(stdout, "Address --> %s\n", address);
  fprintf(stdout, "Port --> %d\n", port);
  fprintf(stdout, "DB save path --> %s\n", path);

  if (run_grpc_client(path, port, address) == -1) {
    fprintf(stderr, "run_grpc_server fail\n");
    exit(EXIT_FAILURE);
  } 

  return 0;
}