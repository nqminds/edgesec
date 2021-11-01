# Configuration file structure

Below is an example of the configuration file that is passed as a parameter to ```edgesec``` tool:
```ini
[system]
binPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
hashIpCommand = ""
createInterfaces = true
ignoreErrorOnIfCreate = true
allowAllConnections = false
apDetect = false
defaultOpenVlanId = 0
killRunningProcess = true
execAp = true
execRadius = true
execDhcp = true

[capture]
captureInterface = "wls1"
promiscuous = false
bufferTimeout = 10
processInterval = 10
immediate = false
db = "./pcap.sqlite"
syncAddress = ""
syncPort = 0

[supervisor]
domainServerPath = /tmp/edgesec-domain-server

[ap]
apBinPath = "./hostapd"
apFilePath = "/tmp/hostapd.conf"
apLogPath = "/tmp/hostapd.log"
interface = "wifiap0"
ssid = "IOTH_IMX7"
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
servers="8.8.4.4,8.8.8.8"

[dhcp]
dhcpBinPath = "/usr/sbin/dnsmasq"
dhcpConfigPath = "/tmp/dnsmasq.conf"
dhcpScriptPath = "/tmp/dnsmasq_exec.sh"
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

[connections]
con1 = "d,04:f0:21:5a:f4:c4,0,1,1234554321"
con2 = "d,30:52:cb:e9:00:8f,1,1,1234554321"
con3 = "d,40:b4:cd:f1:18:bc,2,1,1234554321"
con4 = "d,60:70:c0:0a:23:ba,3,1,1234554321"
con5 = "d,00:0f:00:70:62:88,4,1,1234554321"
con6 = "d,9c:ef:d5:fd:db:56,5,1,1234554321"
con7 = "d,c0:ee:fb:d5:5a:ec,6,1,1234554321"
con8 = "a,00:0f:00:70:62:88,7,1,1234554321"

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

The configuration file is based on the ```ini``` file type format. Each parameter in the file is set using a key and a value pair. The ```edgesec``` configuration file is composed of the following groups:
* *[system]*
* *[capture]*
* *[supervisor]*
* *[hostapd]*
* *[radius]*
* *[nat]*
* *[dns]*
* *[dhcp]*
* *[connections]*
* *[interfaces]*

## [system] group
The system group contains all the parameters that are reponsible to configure the ```edgesec``` system tool paths, the hashes of the system binaries and tool flags.

### binPath (string)
A list of systems binary paths separated with ":" used by the ```edgesec``` tool to configure interfaces, etc.

### hashIpCommand (string)
A list of hashes for each system binary used by the tool. [WIP]

### createInterfaces (boolean)
```edgesec``` will create subnetnetwork interfaces if the flag is set to ```true```. If set to ```false``` one will have to use a similar service to ```dhcpcd``` to preconfigure the network interfaces.

### ignoreErrorOnIfCreate (boolean)
If set to ```true```, ```edgesec``` will ignore the "network interface already exists" error. This flag is to be used if the network interfaces are already preconfigured.

### allowAllConnections (boolean)
If set to ```true```, ```edgesec``` will allow all WiFi connection requests regarding of the MAC value.

### apDetect (boolean)
If set to ```true```, ```edgesec``` will try to detect the WiFi network interfaces that supports VLAN capability. The detected network interface will be used by ```hostapd``` service to create an AP.

### defaultOpenVlanId (integer)
The default VLAN ID positive integer number assigned to new devices if ```allowAllConnections``` flag is set to ```true```.

### killRunningProcess (boolean)
If set to true the current running ```edgesec``` will terminate exisiting running ```edgesec``` processes.

### setIpForward (boolean)
If set to true ```edgesec``` will set the ip forward os system param.

### execHostapd (boolean)
If set to ```true```, ```edgesec``` will execute the ```hostapd``` service using ```excve``` system command. If set to ```false``` the ```hostapd``` service has to be run before executing ```edgesec```.

### execRadius (boolean)
If set to ```true```, ```edgesec``` will execute the ```radius``` service.

### execDhcp (boolean)
If set to ```true```, ```edgesec``` will execute the ```dhcp``` service.

## [capture] group
The capture group contains all the parameters that are reponsible to configure the ```capture``` app service.

### captureInterface (string)
The name of the capture interface. If set to "any" the service will traffic from all interfaces.

### filter (string)
The pcap lib capture filter.

### promiscuous (boolean)
If set to ```true``` the capture interface is set to promiscuous mode. The default value is ```false```.

### immediate (boolean)
If set to ```true``` the capture interface is set to immediate mode. The default value is ```false```.

### bufferTimeout (number)
The timeout in milliseconds to read a packet. The default value is 10.

### processInterval (number)
The interval in milliseconds to process a packet from the queue. The default value is 10.

### fileWrite (boolean)
Write the packet data to file(s).

### dbWrite (boolean)
If set to true the capture service will store the packet into an sqlite db

### dbSync (boolean)
If set to true the sqlite packets db will be synced

### dbPath (string)
Absolute path to the sqlite3 dbs.

### dbSyncAddress (string)
The web address for sqlite syncing

### dbSyncPort (number)
The port of the web address for sqlite syncing

## [supervisor] group
The supervisor group defines the parameters to run the supervisor service.

### domainServerPath (string)
The absolute path to the UNIX domain socket used by the supervisor service.

## [hostapd] group
The hostapd groups defines all the paremeters to run ```hostapd``` service. Most of the parameters are inherited from the ```hostapd``` config file.

### hostapdBinPath (string)
Absolute path to the ```hostapd``` binary.

### hostapdFilePath (string)
Absolute path to the ```hostapd``` configuration file.

### hostapdLogPath (string)
Absolute path to the ```hostapd``` log file. If empty no log file is generated

### interface (string)
Inherited from [hostapd.conf](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)

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
The connecting client IP with format ```x.y.z.q```. Current config uses ```localhost``` (127.0.0.1).

### clientMask (integer)
The client IP network mask encoding bit-length of the prefix.

### serverIP (string)
The RADIUS server IP. Current config uses ```localhost``` (127.0.0.1).

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
A comma delimited string of dns server IP addresses with the format ```x.y.z.q,a.b.c.d,...```.

## [dhcp] group
The dhpc groups defines the parameters for the DHCP server configuration.

### dhcpConfigPath (string)
The absolute path to the DHCP server configuration file

### dhcpScriptPath (string)
The absolute path to the DHCP server aditional executable script.

## [connections] group
The connections groups defines the parameters for devices that connect to the WiFi AP.

### con(idx) (string)
The ```con``` indexed by ```idx≥0``` defines all the MAC addresses and WiFi passwords for devices that are allowed to connect to the WiFi AP. It has the following format:
```
d|a,aa:bb:cc:dd:ee:ff,x,y,pass
```
where:

 - ```d|a``` - (d)eny or (a)llow the device with the given MAC to connect to the WiFi AP,
 - ```aa:bb:cc:dd:ee:ff``` - the given MAC address of the device,
 - ```x``` - denotes the VLAN ID integer assigned to the device,
 - ```y``` - if ```1``` the device is allowed NAT, ```0``` otherwise,
 - ```pass``` - the WiFi password used by the device to connect to the WiFi AP.

## [interfaces] groups
The interfaces group defines the parameters for WiFi subnet interfaces.

### subnetMask (string)
The WiFi subnet mask with format ```x.y.z.q```.

### if(idx) (string)
The ```if``` indexed by ```idx≥0``` defines the network interfaces for a particular subnet. It has the following format:
```
vlanid,ip0,ipn,mask
```
where
 - ```vlanid``` - is the VLAN ID,
 - ```ip0``` - the subnet starting IP address with format ```x.y.z.q```,
 - ```ipn``` - the subnet ending IP address with format ```x.y.z.q``` and
 - ```mask``` - the subnet mask IP address with format ```x.y.z.q```.

# Running edgesec

## Recommended ports:

- `8512` for `capsrv`
- `8513` for `restsrv`
- `8514` for `revsrv` and `revclient`

## EDGESec Edge device

### Running edgesec tool with debug info and master password `12345`

```bash
sudo ./src/edgesec -c config.ini -s 12345 -ddddddddd
```

### Running edgesec tool without debug info and master password `12345`

```bash
sudo ./src/edgesec -c config.ini -s 12345
```

### Running capsrv with syncing of `br10` interface to `localhost:8512` with grpc CA located in `/cert/CA/CA.pem` and data stored in `./db` folder, with debug

_Capture Server_

```bash
sudo ./src/capsrv -i br10 -t 10 -n 10 -y default -w -s -p ./db -a localhost -o 8512 -k ./cert/CA/CA.pem -r 1000000,100 -dddddddddd
```

### Running capsrv with syncing of `br10` interface to `localhost:8512` with grpc CA located in `/cert/CA/CA.pem` and data stored in `./db` folder, without debug

```bash
sudo ./src/capsrv -i br10 -t 10 -n 10 -y default -w -s -p ./db -a localhost -o 8512 -k ./cert/CA/CA.pem -r 1000000,100
```

### Running capsrv in cleaning mode only

Runs capture server in cleaning mode only.

Scans `./db/pcap-meta.sqlite` until PCAP capture
has reached `-b 20971520` KiB (aka 20 GiB).

```bash
./src/capsrv -p ./db -b 20971520 -dddddddd
```

### Running restsrv on port `8513` with TLS certificate generation for `localhost` in debug mode:

```bash
sudo ./src/restsrv -s /tmp/edgesec-domain-server -p 8513 -z 32 -c localhost -t -dddddddd
```

### Running restsrv on port `8513` with TLS certificate generation for `localhost` in non debug:

```bash
sudo ./src/restsrv -s /tmp/edgesec-domain-server -p 8513 -z 32 -c localhost -t
```

### Running revclient to `localhost:8514` with grpc CA located in `/cert/CA/CA.pem` and data stored in `./db` folder, with debug

_GRPC Reverse Connection Client_

Normally, you'd want to connect to a cloud server, but for testing, we can use `localhost`.
Port and cert should match parameters passed to `revsrv`.

```bash
sudo ./src/revclient -f ./db -a localhost -p 8514 -c ./cert/CA/CA.pem -dddddddd
```

### Running revclient to `localhost:8514` without grpc CA and data stored in `./db` folder, without debug

```bash
sudo ./src/revclient -f ./db -a localhost -p 8514
```

### SystemD services

When creating the services `capsrv`, `restrsrv` and `revclient` should depend on `edgesec`.

## Cloud server

The following programs are designed to run on a publically accesible server,
that an EDGESec device can connect to.

### Running revsrv on port `8514`

_GRPC Reverse Connection Server_

The GRPC certificate authority (`-a <example.CA.pem>`) MUST match the certificate authority
passed to `revclient` on the EDGEsec device.

Make sure that your server SSL certificate has the appropriate hostname (e.g. `localhost`, or `edgesec-1.nqm-1.com`).

```bash
sudo ./revsrv -p 8514 -a /etc/edgesec/CA/CA.pem -c /etc/edgesec/revsrv/server.crt -k /etc/edgesec/revsrv/server.key -dddddd
```
