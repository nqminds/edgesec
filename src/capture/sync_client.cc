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

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using sqlite_sync::Synchroniser;
using sqlite_sync::RegisterDbRequest;
using sqlite_sync::RegisterDbReply;
using sqlite_sync::SyncDbStatementRequest;
using sqlite_sync::SyncDbStatementReply;

extern "C" uint32_t run_register_db(char *address, char *name);
extern "C" uint32_t run_sync_db_statement(char *address, char *name, char *statement);

class SynchroniserClient {
 public:
  SynchroniserClient(std::shared_ptr<Channel> channel)
      : stub_(Synchroniser::NewStub(channel)) {}

  uint32_t RegisterDb(const std::string& name) {
    // Data we are sending to the server.
    RegisterDbRequest request;
    request.set_name(name);

    // Container for the data we expect from the server.
    RegisterDbReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->RegisterDb(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.status();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return 0;
    }
  }

  uint32_t SyncDbStatement(const std::string& name, const std::string& statement) {
    SyncDbStatementRequest request;
    SyncDbStatementReply reply;
    ClientContext context;

    request.set_name(name);
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
uint32_t run_register_db(char *address, char *name)
{
  SynchroniserClient syncroniser(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
  log_trace("RegisterDb with name=%s and address=%s", name, address);
  return syncroniser.RegisterDb(name);
}

// extern "C"
uint32_t run_sync_db_statement(char *address, char *name, char *statement)
{
  SynchroniserClient syncroniser(grpc::CreateChannel(address, grpc::InsecureChannelCredentials()));
  log_trace("SyncDbStatement with name=%s and address=%s", name, address);
  return syncroniser.SyncDbStatement(name, statement);
}

// int main(int argc, char** argv) {
//   char *address = "localhost:12345";
//   char *name = "world-db";
//   char *statement =
//     "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL);"
//     "INSERT INTO test VALUES(1, \"test1\");"
//     "INSERT INTO test VALUES(2, \"test2\");"
//     "INSERT INTO test VALUES(3, \"test3\");"
//     "INSERT INTO test VALUES(4, \"test4\");";

//   uint32_t status = run_register_db(address, name);
//   std::cout << "RegisterDb received: " << status << std::endl;
//   status = run_sync_db_statement(address, name,statement);
//   std::cout << "SyncDbStatement received: " << status << std::endl;
//   return 0;
// }