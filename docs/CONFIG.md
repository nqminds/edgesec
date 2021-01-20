# Configuration file structure

Below is an example of the configuration file that is passed as a parameter to ```edgesec``` tool:
```ini
[system]
binPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
hashIpCommand = ""
createInterfaces = false
ignoreErrorOnIfCreate = false
allowAllConnections = false
apDetect = false
execHostapd = false
defaultOpenVlanId = 0
execRadius = false

[supervisor]
domainServerPath = /tmp/edgesec-domain-server

[hostapd]
hostapdBinPath = "./hostapd"
hostapdFilePath = "/tmp/hostapd.conf"
interface = "wlan5"
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
natInterface = "wlan3"

[connections]
con1 = "d,04:f0:21:5a:f4:c4,0,1,1234554321"
con2 = "d,30:52:cb:e9:00:8f,1,1,1234554321"
con3 = "d,40:b4:cd:f1:18:bc,2,1,1234554321"
con4 = "d,60:70:c0:0a:23:ba,3,1,1234554321"
con5 = "d,00:0f:00:70:62:88,4,1,1234554321"
con6 = "d,9c:ef:d5:fd:db:56,5,1,1234554321"
con7 = "d,c0:ee:fb:d5:5a:ec,6,1,1234554321"
con8 = "a,00:0f:60:0b:6a:07,7,1,1234554321"

[interfaces]
subnetMask = "255.255.255.0"
if0 = "br0,10.0.0.1,10.0.0.255"
if1 = "br1,10.0.1.1,10.0.1.255"
if2 = "br2,10.0.2.1,10.0.2.255"
if3 = "br3,10.0.3.1,10.0.3.255"
if4 = "br4,10.0.4.1,10.0.4.255"
if5 = "br5,10.0.5.1,10.0.5.255"
if6 = "br6,10.0.6.1,10.0.6.255"
if7 = "br7,10.0.7.1,10.0.7.255"
if8 = "br8,10.0.8.1,10.0.8.255"
if9 = "br9,10.0.9.1,10.0.9.255"
if10 = "br10,10.0.10.1,10.0.10.255"
```

The configuration file is based on the ```ini``` file type format. Each parameter in the file is set using a key and a value pair. The ```edgesec``` configuration file is composed of the following groups:
* *[system]*
* *[supervisor]*
* *[hostapd]*
* *[radius]*
* *[nat]*
* *[connections]*
* *[interfaces]*

## System group
The system group contains all the parameters that are reponsible to configure the ```edgesec``` system tool paths, the hashes of the system binaries and tool flags.

### binPath [string]
A list of systems binary paths separated with ":" used by the ```edgesec``` tool to configure interfaces, etc.

### hashIpCommand [string]
A list of hashes for each system binary used by the tool. [WIP]

### createInterfaces [boolean]
```edgesec``` will create subnetnetwork interfaces if the flag is set to ```true```. If set to ```false``` one will have to use a similar service to ```dhcpcd``` to preconfigure the network interfaces.

### ignoreErrorOnIfCreate [boolean]
If set to ```true```, ```edgesec``` will ignore the "network interface already exists" error. This flag is to be used if the network interfaces are already preconfigured.

### allowAllConnections [boolean]
If set to ```true```, ```edgesec``` will allow all WiFi connection requests regarding of the MAC value.

### apDetect [boolean]
If set to ```true```, ```edgesec``` will try to detect the WiFi network interfaces that supports VLAN capability. The detected network interface will be used by ```hostapd``` service to create an AP.

### execHostapd [boolean]
If set to ```true```, ```edgesec``` will execute the ```hostapd``` service using ```excve``` system command. If set to ```false``` the ```hostapd``` service has to be run before executing ```edgesec```.

### defaultOpenVlanId [integer]
The default VLAN ID positive integer number assigned to new devices if ```allowAllConnections``` flag is set to ```true```.

### execRadius [boolean]
If set to ```true```, ```edgesec``` will execute the ```radius``` service.
