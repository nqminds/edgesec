---
slug: discovery
title: Device Discovery
---

The secure discovery service implements gateway and device discovery suing the network control service and mDNS reflector if available.

For the gateway discovery we use the gRPC protocol and in particular we implemented the reverse access module with the following protocol buffer:

```
syntax = "proto3";

package reverse_access;

// The reverse access service definition.
service Reverser {
  // Send client resource to server
  rpc SendResource (ResourceRequest) returns (ResourceReply) {}

  // Subscribe to client to server commands
  rpc SubscribeCommand (CommandRequest) returns (stream CommandReply) {}
}

message CommandRequest {
  string id = 1;
}

message CommandReply {
  string command = 1;
  string id = 2;
}

message ResourceRequest {
  uint32 type = 1;
  string meta = 2;
  bytes data = 3;
}

message ResourceReply {
  uint32 status = 1;
}
```

The reverse service is used for discovering/listing the connected gateways as well as running generic commands on the gateway.

As the reverse name suggests the reverse syncroniser connects to the cloud endpoint and executes a SubscribeCommand gRPC function that puts the synchroniser into the listening mode. Subsequently the cloud endpoint can send commands to the client. If a command involves accessing a resource then the SendResource function is used with the corresponding parameters.

The second option for device discovery is by using a reflector for mDNS traffic. If a connected device wants to advertise its services to other subnets using mDNS than the reflectro intercepts the mDNS packet and forwards it to all available subnets.

The third option is given by the device monitoring service, which monitors mDNS, DNS and other traffic data and stores the fingerprint and the qury string into the database for subsequent analaysis. The device discovery process can query the most recent mDNS traffic entry from the fingerprint database and find out the needed source and destination MAC address.
