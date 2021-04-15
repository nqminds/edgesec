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

class ReverseClient {
 public:
  ReverseClient(std::shared_ptr<Channel> channel)
      : stub_(Reverser::NewStub(channel)) {}

  int SendResource(const std::string& meta) {
    ResourceRequest request;
    ResourceReply reply;
    ClientContext context;

    request.set_meta(meta);
    Status status = stub_->SendResource(&context, request, &reply);

    if (status.ok()) {
      std::cout << reply.status() << std::endl;
      return 0;
    } else {
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
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
        // Here process the reply
        std::cout << "Received." << std::endl;
        SendResource("Files for meta");
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
};

int run_grpc_client(char *path, int port, char *address)
{
  char grpc_address[MAX_WEB_PATH_LEN];
  snprintf(grpc_address, MAX_WEB_PATH_LEN, "%s:%d", address, port);

  fprintf(stdout,"Connecting to %s...\n", grpc_address);
  ReverseClient reverser(grpc::CreateChannel(grpc_address, grpc::InsecureChannelCredentials())); 
  if (reverser.SubscribeCommand("12345") < 0) {
    fprintf(stderr,"grpc SubscribeCommand failed\n");
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