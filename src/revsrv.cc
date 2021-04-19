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
 * @file revsrv.cc 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the reverse server.
 */

#include <iostream>
#include <sstream>
#include <memory>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sys/un.h>
#include <sys/socket.h>



#include <grpcpp/grpcpp.h>

#include "reverse_access.grpc.pb.h"

#include "supervisor/domain_server.h"
#include "utils/eloop.h"
#include "utils/os.h"
#include "utils/log.h"
#include "version.h"
#include "revcmd.h"

#define OPT_STRING    ":f:p:dvh"
#define USAGE_STRING  "\t%s [-f path] [-p port] [-d] [-h] [-v]"
#define CONTROL_INTERFACE_NAME  "revcontrol"
#define COMMAND_SEPARATOR       0x20

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;
using reverse_access::Reverser;
using reverse_access::CommandRequest;
using reverse_access::CommandReply;
using reverse_access::ResourceRequest;
using reverse_access::ResourceReply;

static __thread char version_buf[10];
static REVERSE_COMMANDS control_command;
std::string command_args;
std::string control_response;

std::mutex command_lock;
std::condition_variable command_v;

std::mutex response_lock;
std::condition_variable response_v;

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
  fprintf(stdout, "revsrv app version %s\n",
    get_static_version_string(REVSRV_VERSION_MAJOR, REVSRV_VERSION_MINOR,
    REVSRV_VERSION_PATCH));
}

void show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(app_name));
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-f folder\t Folder to save synced files\n");
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

void process_app_options(int argc, char *argv[], int *port, uint8_t *verbosity)
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

std::size_t split_string(std::vector<std::string> &string_list, std::string &str, char delim)
{
  std::stringstream str_stream(str);
  std::string out;

  while (std::getline(str_stream, out, delim)) {
    string_list.push_back(out);
  }

  return string_list.size();
}

void wait_reverse_command(REVERSE_COMMANDS cmd, std::string &args)
{
  {
    std::lock_guard<std::mutex> lk(command_lock);
    control_command = cmd;
    command_args = args;
  }

  command_v.notify_one();

  {
    std::unique_lock<std::mutex> lk(command_lock);
    command_v.wait(lk, []{return control_command == REVERSE_CMD_UNKNOWN;});
  }
}

void wait_reverse_response(std::string response)
{
  {
    std::lock_guard<std::mutex> lk(response_lock);
    control_response = response;
  }

  response_v.notify_one();

  {
    std::unique_lock<std::mutex> lk(response_lock);
    response_v.wait(lk, []{return !control_response.size();});
  }
}

class ReverserServiceImpl final : public Reverser::Service {
 public:
  explicit ReverserServiceImpl() {}

  Status SubscribeCommand(ServerContext* context, const CommandRequest* request, ServerWriter<CommandReply>* writer) override {
    while(true) {
      CommandReply reply;
      std::unique_lock<std::mutex> lk(command_lock);
      command_v.wait(lk, []{return control_command != REVERSE_CMD_UNKNOWN;});
      reply.set_command(control_command);
      reply.set_args(command_args);
      writer->Write(reply);
      control_command = REVERSE_CMD_UNKNOWN;
      command_args.clear();
      lk.unlock();
      command_v.notify_one();
    }
    return Status::OK;
  }

  Status SendResource(ServerContext* context, const ResourceRequest* request, ResourceReply* reply) override {
    fprintf(stdout, "%s", request->data().c_str());
    wait_reverse_response(request->data());
    reply->set_status(0);
    return Status::OK;
  }

  private:
    std::string meta_;
    mutable std::mutex mtx_;
};

char * process_cmd_str(char *buf, ssize_t len)
{
  char *cmd_line = (char *)os_malloc(len + 1);
  if (cmd_line == NULL) {
    log_err_ex("malloc");
    return NULL;
  }

  os_memcpy(cmd_line, buf, len);
  cmd_line[len] = '\0';

  rtrim(cmd_line, NULL);

  return cmd_line;
}

ssize_t process_command(std::vector<std::string> &cmd_list, char **response_buf)
{
  ssize_t buf_size = 0;
  std::string args;
  *response_buf = NULL;

  if (cmd_list.size()) {
    std::string cmd = cmd_list.front();
    if (cmd_list.size() > 1)
      args = cmd_list.at(1);

    if (strcmp(cmd.c_str(), REVERSE_CMD_STR_LIST) == 0) {
      log_trace("Processing command %s", REVERSE_CMD_STR_LIST);
      wait_reverse_command(REVERSE_CMD_LIST, args);
      log_trace("Finished processing");
    } else if (strcmp(cmd.c_str(), REVERSE_CMD_STR_GET) == 0) {
      log_trace("Processing command %s", REVERSE_CMD_STR_GET);
      wait_reverse_command(REVERSE_CMD_GET, args);
      log_trace("Finished processing");
    } else {
      log_trace("Unknown command %s", cmd.c_str());
    }
  }

  std::unique_lock<std::mutex> lk(response_lock);
  response_v.wait(lk, []{return control_response.size();});

  log_trace("Received gRPC response");
  buf_size = control_response.size() + 1;
  *response_buf = (char *)os_zalloc(buf_size);
  if (*response_buf == NULL) {
    log_err("os_zalloc");
    lk.unlock();
    response_v.notify_one();

    return 0;
  }
  os_memcpy(*response_buf, control_response.data(), control_response.size());

  control_response.clear();

  lk.unlock();
  response_v.notify_one();

  return buf_size;
}

void eloop_read_sock_handler(int sock, void *eloop_ctx, void *sock_ctx)
{
  char buf[MAX_DOMAIN_RECEIVE_DATA];

  char *client_addr = (char *)os_malloc(sizeof(struct sockaddr_un));
  ssize_t num_bytes = read_domain_data(sock, buf, 100, client_addr);
  if (num_bytes == -1) {
    log_trace("read_domain_data fail");
    os_free(client_addr);
  }

  char *cmd_line = process_cmd_str(buf, num_bytes);
  log_trace("%s", cmd_line);

  std::string cmd_str(cmd_line);
  os_free(cmd_line);

  std::vector<std::string> cmd_list;

  split_string(cmd_list, cmd_str, COMMAND_SEPARATOR);
  char *response_buf = NULL;
  ssize_t buf_size = process_command(cmd_list, &response_buf);
  if (response_buf != NULL) {
    write_domain_data(sock, response_buf, buf_size, client_addr);
    os_free(response_buf);
  }

  os_free(client_addr);
  return;
}

void run_control_socket(std::string &name)
{
  int sock;

  log_info("Control socket at %s", name.c_str());

  if (eloop_init()) {
		log_debug("Failed to initialize event loop");
		return;
	}

  if ((sock = create_domain_server((char *)name.c_str())) == -1) {
    log_trace("create_domain_server fail");
    eloop_destroy();
    return;
  }

  if (eloop_register_read_sock(sock, eloop_read_sock_handler, NULL, NULL) ==  -1) {
    log_trace("eloop_register_read_sock fail");
    eloop_destroy();
    close(sock);
    return;
  }

  log_info("Running event loop");
  eloop_run();

  // close_supervisor(domain_sock);
  eloop_destroy();
}

void run_grpc_server(int port)
{
  ReverserServiceImpl reverser;
  std::string server_address("0.0.0.0:");
  server_address += std::to_string(port);

  grpc::EnableDefaultHealthCheckService(true);
  ServerBuilder builder;

  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  builder.RegisterService(&reverser);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  log_info("Server listening on %s", server_address.c_str());

  server->Wait();
}

int main(int argc, char** argv) {
  uint8_t verbosity = 0;
  uint8_t level = 0;
  int port = -1;
  std::string ctrlif(CONTROL_INTERFACE_NAME);

  process_app_options(argc, argv, &port, &verbosity); 

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

  fprintf(stdout, "Starting reverse client with:\n");
  fprintf(stdout, "Port --> %d\n", port);

  control_response.clear();

  std::thread control_thread(run_control_socket, std::ref(ctrlif));
  run_grpc_server(port);

  return 0;
}