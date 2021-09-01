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
 * @file sync_client.cc
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the sqlite db syncing utils.
 */

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "sqlite_sync.grpc.pb.h"

#include "../utils/log.h"
#include "../utils/os.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using sqlite_sync::Synchroniser;
using sqlite_sync::RegisterDbRequest;
using sqlite_sync::RegisterDbReply;
using sqlite_sync::SyncDbStatementRequest;
using sqlite_sync::SyncDbStatementReply;

extern "C" uint32_t run_register_db(char *ca, char *address, char *name);
extern "C" uint32_t run_sync_db_statement(char *ca, char *address, char *name, bool default_db, char *statement);

class SynchroniserClient {
 public:
  SynchroniserClient(std::shared_ptr<Channel> channel)
      : stub_(Synchroniser::NewStub(channel)) {}

  uint32_t RegisterDb(const std::string& name) {
    RegisterDbRequest request;
    RegisterDbReply reply;
    ClientContext context;
    request.set_name(name);
    Status status = stub_->RegisterDb(&context, request, &reply);

    if (status.ok()) {
      return reply.status();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return 0;
    }
  }

  uint32_t SyncDbStatement(const std::string& name, bool default_db, const std::string& statement) {
    SyncDbStatementRequest request;
    SyncDbStatementReply reply;
    ClientContext context;

    request.set_name(name);
    request.set_default_db(default_db);
    request.set_statement(statement);

    // The actual RPC.
    Status status = stub_->SyncDbStatement(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.status();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return 0;
    }

  }
 private:
  std::unique_ptr<Synchroniser::Stub> stub_;
};

// extern "C" 
uint32_t run_register_db(char *ca, char *address, char *name)
{
  std::shared_ptr<grpc::ChannelCredentials> creds;
  if (ca != NULL) {
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca;
    creds = grpc::SslCredentials(ssl_opts);
  } else {
    creds = grpc::InsecureChannelCredentials();
  }

  SynchroniserClient syncroniser(grpc::CreateChannel(address, creds));
  log_trace("RegisterDb with name=%s and address=%s", name, address);
  return syncroniser.RegisterDb(name);
}

// extern "C"
uint32_t run_sync_db_statement(char *ca, char *address, char *name, bool default_db, char *statement)
{
  std::shared_ptr<grpc::ChannelCredentials> creds;
  if (ca != NULL) {
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = ca;
    creds = grpc::SslCredentials(ssl_opts);
  } else {
    creds = grpc::InsecureChannelCredentials();
  }

  SynchroniserClient syncroniser(grpc::CreateChannel(address, creds));
  log_trace("SyncDbStatement with name=%s, address=%s and default_db=%d", name, address, default_db);
  return syncroniser.SyncDbStatement(name, default_db, statement);
}
