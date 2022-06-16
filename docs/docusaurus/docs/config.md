---
slug: config
title: Configuration File
---

Below is an example of the configuration file that is passed as a parameter to `edgesec` tool:

```
[system]
binPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
createInterfaces = true
ignoreErrorOnIfCreate = true
allowAllConnections = true
allowAllNat = true
apDetect = false
generateSsid = true
allocateVlans = true
defaultOpenVlanId = 0
quarantineVlanId = 10
execAp = false
execRadius = true
execDhcp = true
execCapture = true
execMdnsForward = true
execIptables = true
setIpForward = true
cryptDbPath = "./crypt.sqlite"
pidFilePath = "/var/run/edgesec.pid"

[capture]
captureDbPath = "./capture.sqlite"
filter = ""
promiscuous = false
bufferTimeout = 10
immediate = false

[supervisor]
supervisorControlPort = 32001
supervisorControlPath = "/tmp/edgesec-control-server"

[ap]
apBinPath = "./hostapd"
apFilePath = "/tmp/hostapd.conf"
apLogPath = "/tmp/hostapd.log"
interface = "wifiap0"
vlanTaggedInterface = ""
ssid = "IOTH_TEST"
wpaPassphrase = "1234554321"
bridge = "br0"
driver = "nl80211"
hwMode = "g"
channel = 11
wmmEnabled = 1
authAlgs = 1
wpa = 2
wpaKeyMgmt = "WPA-PSK"
rsnPairwise = "CCMP"
ctrlInterface = "/var/run/hostapd"
macaddrAcl = 2
dynamicVlan = 1
vlanBridge = "br"
vlanFile = "/tmp/hostapd.vlan"
loggerStdout = -1
loggerStdoutLevel = 0
loggerSyslog = -1
loggerSyslogLevel = 0
ignoreBroadcastSsid = 0
wpaPskRadius = 2

[radius]
port = 1812
clientIP = "127.0.0.1"
clientMask = 32
serverIP = "127.0.0.1"
serverMask = 32
secret = "radius"

[nat]
natInterface = "enp2s0"

[dns]
servers = "8.8.4.4,8.8.8.8"
mdnsReflectIp4 = true
mdnsReflectIp6 = true
mdnsFilter = "src net 10.0 and dst net 10.0"

[dhcp]
dhcpBinPath = "/usr/sbin/dnsmasq"
dhcpConfigPath = "/tmp/dnsmasq.conf"
dhcpScriptPath = "/tmp/dnsmasq_exec.sh"
dhcpLeasefilePath = "/tmp/dnsmasq.leases"
dhcpRange0 = "0,10.0.0.2,10.0.0.254,255.255.255.0,24h"
dhcpRange1 = "1,10.0.1.2,10.0.1.254,255.255.255.0,24h"
dhcpRange2 = "2,10.0.2.2,10.0.2.254,255.255.255.0,24h"
dhcpRange3 = "3,10.0.3.2,10.0.3.254,255.255.255.0,24h"
dhcpRange4 = "4,10.0.4.2,10.0.4.254,255.255.255.0,24h"
dhcpRange5 = "5,10.0.5.2,10.0.5.254,255.255.255.0,24h"
dhcpRange6 = "6,10.0.6.2,10.0.6.254,255.255.255.0,24h"
dhcpRange7 = "7,10.0.7.2,10.0.7.254,255.255.255.0,24h"
dhcpRange8 = "8,10.0.8.2,10.0.8.254,255.255.255.0,24h"
dhcpRange9 = "9,10.0.9.2,10.0.9.254,255.255.255.0,24h"
dhcpRange10 = "10,10.0.10.2,10.0.10.254,255.255.255.0,24h"

[interfaces]
if0 = "0,10.0.0.1,10.0.0.255,255.255.255.0"
if1 = "1,10.0.1.1,10.0.1.255,255.255.255.0"
if2 = "2,10.0.2.1,10.0.2.255,255.255.255.0"
if3 = "3,10.0.3.1,10.0.3.255,255.255.255.0"
if4 = "4,10.0.4.1,10.0.4.255,255.255.255.0"
if5 = "5,10.0.5.1,10.0.5.255,255.255.255.0"
if6 = "6,10.0.6.1,10.0.6.255,255.255.255.0"
if7 = "7,10.0.7.1,10.0.7.255,255.255.255.0"
if8 = "8,10.0.8.1,10.0.8.255,255.255.255.0"
if9 = "9,10.0.9.1,10.0.9.255,255.255.255.0"
if10 = "10,10.0.10.1,10.0.10.255,255.255.255.0"
```

The configuration file is based on the `ini` file type format. Each parameter in the file is set using a key and a value pair. The `edgesec` configuration file is composed of the following groups:

- _[system]_
- _[capture]_
- _[supervisor]_
- _[hostapd]_
- _[radius]_
- _[nat]_
- _[dns]_
- _[dhcp]_
- _[connections]_
- _[interfaces]_

## [system] group

The system group contains all the parameters that are reponsible to configure the `edgesec` system tool paths, the hashes of the system binaries and tool flags.

### binPath (string)

A list of systems binary paths separated with ":" used by the `edgesec` tool to configure interfaces, etc.

### createInterfaces (boolean)

`edgesec` will create subnetnetwork interfaces if the flag is set to `true`. If set to `false` one will have to use a similar service to `dhcpcd` to preconfigure the network interfaces.

### ignoreErrorOnIfCreate (boolean)

If set to `true`, `edgesec` will ignore the "network interface already exists" error. This flag is to be used if the network interfaces are already preconfigured.

### allowAllConnections (boolean)

If set to `true`, `edgesec` will allow all WiFi connection requests regarding of the MAC value.

### allowAllNat (boolean)

If set to `true`, `edgesec` will allow all NAT connection requests regarding of the MAC value.

### apDetect (boolean)

If set to `true`, `edgesec` will try to detect the WiFi network interfaces that supports VLAN capability. The detected network interface will be used by `hostapd` service to create an AP.

### generateSsid (boolean)

If set to `true`, `edgesec` will generate the SSID WiFi name based on hostname. If `false` the SSID name will be `ssid` param from `ap` section.

### allocateVlans (boolean)

If set to `true`, `edgesec` will randomly assign a VLAN ID to a newly connected device.

### defaultOpenVlanId (integer)

The default VLAN ID positive integer number assigned to new devices if `allowAllConnections` flag is set to `true`.

### quarantineVlanId (integer)

The VLAN ID assigned to devices that are quarantined.

### execAp (boolean)

If set to `true`, `edgesec` will execute the `hostapd` service using `excve` system command. If set to `false` the `hostapd` service has to be run before executing `edgesec`.

### execRadius (boolean)

If set to `true`, `edgesec` will execute the `radius` service.

### execDhcp (boolean)

If set to `true`, `edgesec` will execute the `dhcp` service.

### execCapture (boolean)

If set to `true`, `edgesec` will execute the `capture` service.

### execMdnsForward (boolean)

If set to `true`, `edgesec` will execute the `mdnsf` service.

### execIptables (boolean)

If set to `true`, `edgesec` will execute the `iptables` command.

### setIpForward (boolean)

If set to true `edgesec` will set the ip forward os system param.

### cryptDbPath (string)

The path to the `crypt` sqlite db.

### pidFilePath (string)

The path to the edgesec PID file.

## [capture] group

The capture group contains all the parameters that are reponsible to configure the `capture` app service.

### filter (string)

The pcap lib capture filter.

### promiscuous (boolean)

If set to `true` the capture interface is set to promiscuous mode. The default value is `false`.

### bufferTimeout (number)

The timeout in milliseconds to read a packet. The default value is 10.

### immediate (boolean)

If set to `true` the capture interface is set to immediate mode. The default value is `false`.

### dbSync (boolean)

If set to true the sqlite packets db will be synced

### dbSyncAddress (string)

The web address for sqlite syncing

### dbSyncPort (number)

The port of the web address for sqlite syncing

### syncCaPath (string)

The path to the certificate authority file used for gRPC syncing

### command (string)

The UNIX domain command used by the capture service

## [supervisor] group

The supervisor group defines the parameters to run the supervisor service.

### supervisorControlPort (number)

The supervisor server control port number.

### supervisorControlPath (string)

The absolute path to the UNIX domain socket used by the supervisor service.

## [ap] group

The ap groups defines all the paremeters to run `ap` service. Most of the parameters are inherited from the `hostapd` config file.

### apBinPath (string)

Absolute path to the `hostapd` binary.

### apFilePath (string)

Absolute path to the `hostapd` configuration file.

### apLogPath (string)

Absolute path to the `hostapd` log file. If empty no log file is generated

### interface (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### vlanTaggedInterface (string)

Interface name for vlan tagging

### ssid (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### wpaPassphrase (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### bridge (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### driver (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### hwMode (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### channel (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### wmmEnabled (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### authAlgs (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### wpa (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### wpaKeyMgmt (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### rsnPairwise (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### ctrlInterface (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### macaddrAcl (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### dynamicVlan (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### vlanBridge (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### vlanFile (string)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### loggerStdout (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### loggerStdoutLevel (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### loggerSyslog (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### loggerSyslogLevel (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### ignoreBroadcastSsid (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

### wpaPskRadius (integer)

Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

## [radius] group

The radius group defines the port, IP and network mask for creating the RADIUS server.

### port (integer)

The port value for the RADIUS server.

### clientIP (string)

The connecting client IP with format `x.y.z.q`. Current config uses `localhost` (127.0.0.1).

### clientMask (integer)

The client IP network mask encoding bit-length of the prefix.

### serverIP (string)

The RADIUS server IP. Current config uses `localhost` (127.0.0.1).

### serverMask (integer)

The server IP network mask encoding bit-length of the prefix.

### secret (string)

The RADIUS server password used by the clients.

## [nat] group

The nat group defines the parameter for NAT interface.

### natInterface (string)

The NAT interface name.

## [dns] group

The dns groups defines the parameters for the DNS server configuration.

### servers (string)

A comma delimited string of dns server IP addresses with the format `x.y.z.q,a.b.c.d,...`.

### mdnsReflectIp4 (boolean)

If set to `true` the mdns service will reflect IP4 mdns packets.

### mdnsReflectIp6 (boolean)

If set to `true` the mdns service will reflect IP6 mdns packets.

### mdnsFilter (string)

The `mdns` service filter string used by pcap library to track internal IP connections. The filter is based on the `interface` IP addresses.

## [dhcp] group

The dhpc groups defines the parameters for the DHCP server configuration.

### dhcpBinPath (string)

The path to the DHCP server

### dhcpConfigPath (string)

The path to the DHCP server configuration file

### dhcpScriptPath (string)

The path to the DHCP server aditional executable script

### dhcpLeasefilePath (string)

The path to the DHCP lease file

### dhcpRangei (string)

The DHCP configuration indexed by `i≥0`. It has the followig format:

```
vlanid,ip_low,ip_up,mask,time
```

,where

- `vlanid` - the VLAN ID
- `ip_low` - the lower bound for IP subnet
- `up_low` - the upper bound for IP subnet
- `mask` - the subnet mask
- `time` - the lease time (dnsmasq format)

## [interfaces] groups

The interfaces group defines the parameters for WiFi subnet interfaces.

### ifi (string)

The `if` indexed by `i≥0` defines the network interfaces for a particular subnet. It has the following format:

```
vlanid,ip0,ipn,mask
```

where

- `vlanid` - is the VLAN ID,
- `ip0` - the subnet starting IP address with format `x.y.z.q`,
- `ipn` - the subnet ending IP address with format `x.y.z.q` and
- `mask` - the subnet mask IP address with format `x.y.z.q`.
