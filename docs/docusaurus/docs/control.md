---
slug: control
title: Network Control
---

## The Network Control architecture

The network architecture of the EDGESec tool consist of several services that create and manage connected IoT devices. The below diagram depicts the architecture, which consists of six services:

- Subnet service
- Supervisor service
- RADIUS server
- Software AP service
- DHCP service
- State machine service
- Network Capture service
- Crypt service

![Network architecture](/img/dot_network-control-arch.png)

The management of each service is controlled by the tool engine, which has the ability to configure and start the execution process. First, the engine executes the supervisor service, which has the role of registering network joining and DHCP requests. It also exposes a command interface in the form of a UNIX domain socket that can be used by other application or services the control the connected newtork devices. Second, the engine executes the software access point (AP) service that creates a managed AP, which allows every network device to connect to it. The AP allows setting individual network joining credential for every connecting devices. Third, the engine executes the subnet service which creates subnets for give virtual LAN (VLAN) IDs and IP ranges. The software AP service maps subsequently a connected network device to a subnet. Fourth, the engine executes the DHCP service that has the role of assigning IP addresses to connected devices. Fifth, the engine executes the RADIUS server, which sends access control information to the software AP. The access information contains the network joining credentials and the accept/deny MAC address information. Sixth, the engine execute the state machine service, which represents the core of the network monitoring and management process. The state machine monitors the state of each connected network device by employing information from the supevisor service. It also uses the capture service, which executes self contained traffic capturing routines to monitor the flow of packet and disect identify the device types.

## The Subnet service

This service creates subnets and maps VLAN IDs to a subnet IP range. It uses the Netlink protocol library suite to access network kernel functionality from the user space.

## The Supervisor service

This service supervises the assignment of IP addresses and manages the connectivity structures for a network devices. It exposes a UNIX domain socket as the control interface that can be used by other applications to execute the following commands:

- **PING_SUPERVISOR** - Ping the supervisor
- **HOSTAPD_IF** - Return the hostapd (software AP) control interface
- **ACCEPT_MAC** - Add a MAC address to the accept tlist
- **DENY_MAC** - Remove a MAC address from the accept list
- **ADD_NAT** - Add a MAC address to network address translation (NAT)
- **REMOVE_NAT** - Remove a MAC address from NAT
- **ASSIGN_PSK** - Assign a network credential to a MAC address
- **GET_MAP** - Return the MAC mapper structure for a given MAC address
- **GET_ALL** - Return all MAC mappers structures
- **SET_IP** - Map an IP address to a MAC address
- **ADD_BRIDGE** - Add two MAC addresses to a bridge
- **REMOVE_BRIDGE** - Remove two MAC addresses from a bridge
- **GET_BRIDGES** - List all MAc bridges

The supervisor context below describes the stored structure for all network connected devices:

```c
struct supervisor_context {
  hmap_mac_conn             *mac_mapper;
  hmap_if_conn              *if_mapper;
  hmap_vlan_conn            *vlan_mapper;
  bool                      allow_all_connections;
  char                      hostapd_ctrl_if_path[MAX_OS_PATH_LEN];
  uint8_t                   wpa_passphrase[AP_SECRET_LEN];
  ssize_t                   wpa_passphrase_len;
  char                      nat_interface[IFNAMSIZ];
  int                       default_open_vlanid;
  UT_array                  *config_ifinfo_array;
  struct bridge_mac_list    *bridge_list;
};
```

It contains the mappers between MAC address, VLAN ID, IP address and network credentials. It also contains the mappers for NAT and network bridges.

The interaction between the supervisor and other services is depicted below.

![Supervisor](/img/dot_supervisor.png)

The supervisor and DHPC are separate services that intercat through the control interface. When the DHCP assigns an IP address to a network device it sends the assigned IP to the supervisor through control interface. Subsequently the supervisor saves the IP in the corresponding mapping table. The supervisor also notifies the radius server on the MAC addresses and credentials it can use. Finally the supervisaor also uses the iptables routines to configure the NAT and bridge functinality for each network device.

## Bridge

The supervisor allows connecting two network devices into a bridge. Below is a diagram depicting an example connection between five network devices:

![Bridge](/img/dot_bridge.png)

It important to note that the connection is not transitive. The control interface allows any application to list, add and remove bridge connections. When a connection is being added or removed the corresponding mapping in the supervisor context and the iptables entries are modified.

## NAT

The supervisor can allow or deny network access to a network device. The below picture depicts an example of NAT connection for several devices.

![Nat](/img/dot_nat.png)

As for bridges when a NAT connection is added or removed the iptables is modified accordinlgy.

## Software AP service

The software AP service creates a WiFi access points for network device connection. Currently the edgesec tool uses the hostap software AP service. The configuration structure for the AP service is depicted below:

```c
struct apconf {
  char ap_bin_path[MAX_OS_PATH_LEN];
  char ap_file_path[MAX_OS_PATH_LEN];
  char ap_log_path[MAX_OS_PATH_LEN];
  char interface[IFNAMSIZ];
  char ssid[AP_NAME_LEN];
  char wpa_passphrase[AP_SECRET_LEN];
  char bridge[IFNAMSIZ];
  char driver[AP_DRIVE_LEN];
  char hw_mode[AP_HWMODE_LEN];
  int channel;
  int wmm_enabled;
  int auth_algs;
  int wpa;
  char wpa_key_mgmt[AP_WPA_KEY_MGMT_LEN];
  char rsn_pairwise[AP_RSN_PAIRWISE_LEN];
  char ctrl_interface[MAX_OS_PATH_LEN];
  int macaddr_acl;
  int dynamic_vlan;
  char vlan_bridge[IFNAMSIZ];
  char vlan_file[MAX_OS_PATH_LEN];
  int logger_stdout;
  int logger_stdout_level;
  int logger_syslog;
  int logger_syslog_level;
  int ignore_broadcast_ssid;
  int wpa_psk_radius;
};
```

The main components of the structure are **interface**, **ssid**, **wpa_passphrase** and **ctrl_interface**. The **interface** parameters sets the network interface of the AP. The **ssid** denotes the visible name of the access point to which network devices can connect to. The **wpa_passphrase** denotes the network credentials to join the AP abd the **ctrl_interface** is the UNIX domain socket to manage the AP.

Below is a diagram depicting the connection between the AP and other network services:

![AP](/img/dot_ap.png)

The software AP, which in this case is implemented by hostapd, creates a RADIUS client. The RADIUS client equires for network credentials from RADIUS server. Subsequently the RADIUS server returns the access/deny and credentials packet. The access list and credentials are obtained from the supervisor service.
