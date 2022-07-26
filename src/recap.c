/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief A tool to run the capture with an input pcap file
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <libgen.h>

#define OPT_STRING ":c:f:mdvh"
#define USAGE_STRING "\t%s [-p filename] [-f filename] [-d] [-h] [-v]\n"
const char description_string[] = R"==(
  NquiringMinds EDGESec Network Security Router.

  Creates a secure and paritioned Wifi access point, using vlans,
  and can analyse network traffic.

  Contains multiple services controlled by the tool engine:
    1. Supervisor: registers network joining and DHCP requests.
       Exposes a command interface via a UNIX domain socket.
    2. WiFi Access Point: Manages WiFi AP.
    3. Subnet: Creates subnets, virtual LANs, and IP ranges.
    4. DHCP: Assigns IP addresses to connected devices.
    5. RADIUS: Access control for the WiFi AP using
       credentials/MAC address.
    6. State machine: Networking monitoring and management.
)==";
