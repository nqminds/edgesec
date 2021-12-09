---
slug: /
title: EDGESec Intro
---

EDGESec defines a new architecture and toolset for edge based routers addressing fundamental security weaknesses that impact current IP and IoT router implementations.

## Motivation

Internet technologies and current practice does not address security requirements of edgebased devices very well.

It is a fact that the "admin page" of most routers, wifi devices and webcams is "unsecured". It is perhaps not surprise that a recent Symnatec study showed that ["Routers account for 75% of infected IOT devices"](https://docs.broadcom.com/docs/istr-24-2019-en). The problem is that domain resolution on local Internets and HTTPS certificates do not work well together. Also HTTPS certs assume the private key is secure; how do I do this on a small edge device? EDGESec architecture and toolset implements novel user experience, key distribution, key storage and secure service discovery primitives to address current security shortcomings and provide a new vision for integrated cloud-edge services.

## Problem need

Most internet gateways, indeed most IP addressable device on an internal network have a fundamental weakness, they are not well secured.

It is very hard to install web based certificates, that resolve to local IP addresses. As a result most broadband routers, internet gateways, IOT devices and webcams have insecure administrator access on the local network.

Security assumes if you have access to the network you are trusted. This is clearly a mistaken assumption. Recent research by Symantec shows that 75% of reported attacks on IOT devices were due to router weaknesses.

Edge routers, internal networks and more advanced IoT networking need fundamental innovation to address the security weakness. New architectures are needed for UI bootstrapping, key distribution, key storage, service discovery and addressing that will work as well at the edge as it does on the open internet.

## Ambition

EDGESec toolset provides the following solutions to solve the main IoT gateway security challenges:
1. A mechanism to do network isolation at the IoT gateway level. The network isolation will protect against external and internal entities attacking the connected IoT devices.
2. A secure discovery and peer-to-peer connectivity mechanisms for IoT devices and gateway.
3. A mechanism to store encryption keys and confidential router data.
4. A mechanism to monitor connected IoT devices at the router level. By defining the minimal data collection standards, we have in place a powerful technique that will assist with the early detection and later containment of security threats coming from compromised IoT devices.

We integrate all of the above strategies into a single opensource codebase lays the foundation for a secure IoT gateway and will be used as a standard for IoT device connectivity.

## Technical approach

* [Network Control](control.md) - The network isolation technique is implemented at the WiFi level protocol. We are using the VLAN mechanism to segment the network of connected IoT devices.
* [Network Capture](capture.md) - We use packet sniffers and analysers to monitor and detect compromised IoT devices.
* [Device Discovery](discovery.md) - For device discovery and connectivity between IoT devices and IoT gateway we plan to use the efficient gRPC protocol.
* [Secure Storage](storage.md) - To store the encryption keys and router confidential data we implemented a generic key value store on top of hardware secure storage.
