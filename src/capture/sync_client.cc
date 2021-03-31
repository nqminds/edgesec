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
#include <vector>

#include <grpcpp/grpcpp.h>

#include "sqlite_sync.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using sqlite_sync::Synchroniser;
using sqlite_sync::RegisterDbRequest;
using sqlite_sync::RegisterDbReply;
using sqlite_sync::SyncDbStatementRequest;
using sqlite_sync::SyncDbStatementReply;

class SynchroniserClient {
 public:
  SynchroniserClient(std::shared_ptr<Channel> channel)
      : stub_(Synchroniser::NewStub(channel)) {}

  std::string RegisterDb(const std::string& user) {
    // Data we are sending to the server.
    RegisterDbRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    RegisterDbReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->RegisterDb(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

  std::string SyncDbStatement(const std::vector<std::string>& statement_list) {
    SyncDbStatementRequest request;
    for (int idx = 0; idx < statement_list.size(); idx ++)
      request.add_statement(statement_list[idx]);

    // Container for the data we expect from the server.
    SyncDbStatementReply reply;

    ClientContext context;

    // The actual RPC.
    Status status = stub_->SyncDbStatement(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }

  }
 private:
  std::unique_ptr<Synchroniser::Stub> stub_;
};

int main(int argc, char** argv) {
  std::vector<std::string> colour {"Blue", "Red", "Orange"};
  SynchroniserClient syncroniser(
      grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
  std::string user("world");
  std::string reply = syncroniser.RegisterDb(user);
  std::cout << "Synchroniser received: " << reply << std::endl;
  reply = syncroniser.SyncDbStatement(colour);
  std::cout << "Synchroniser received: " << reply << std::endl;
  return 0;
}