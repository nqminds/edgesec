# ManySecured
[![Github Pages](https://github.com/nqminds/EDGESec/workflows/Github%20Pages/badge.svg?branch=master)](https://github.com/nqminds/EDGESec/actions?query=workflow%3A%22Github+Pages%22)

## docs

See [`./docs`](./docs) for how to build the documentation website.

## Build

Compiling ManySecured is done with CMake.

### Installing Dependencies

On Ubuntu, we need a C compiler, CMake, Doxygen, and libnl-genl-3-dev:

```console
$ sudo apt update && sudo apt install -y cmake build-essentials doxygen libnl-genl-3-dev libnl-route-3-dev graphviz
```

### Compile

```
mkdir -p build/
cd build/
cmake ..
cmake --build -j2 .. # replace 2 with number of threads to use for building
# edgesec software will be at ./src/edgesec
```

## Running

```
./build/src/edgesec -c ./build/config.ini
```

**Enabling verbose debug mode**

```
./build/src/edgesec -c ./build/config.ini -ddddd
```

## HOSTAPD Commands
### PING
Usage:
```
PING
```

### RELOG
Usage:
```
RELOG
```

### NOTE
Usage:
```
NOTE text
```

### STATUS
Usage:
```
STATUS
```

### STATUS-DRIVER
Usage:
```
STATUS-DRIVER
```

### MIB
Usage:
```
MIB
```

### STA-FIRST
Usage:
```
STA-FIRST
```

### STA
Usage:
```
STA mac_address
```

### STA-NEXT
Usage:
```
STA-NEXT mac_address
```

### ATTACH
Usage:
```
ATTACH
```

### DETACH
Usage:
```
DETACH
```

### NEW_STA
Usage:
```
NEW_STA mac_address
```

### DEAUTHENTICATE
Usage:
```
DEAUTHENTICATE mac_address reason=value[1-45]
```

### DISASSOCIATE
Usage:
```
DISASSOCIATE mac_address reason=value[1-45]
```

### POLL_STA
Usage:
```
POLL_STA mac_address
```

### STOP_AP
Usage:
```
STOP_AP
```

### GET_CONFIG
Usage:
```
GET_CONFIG
```

### RELOAD_WPA_PSK
Usage:
```
RELOAD_WPA_PSK
```

### RELOAD
Usage:
```
RELOAD
```

### ENABLE
Usage:
```
ENABLE
```

### DISABLE
Usage:
```
DISABLE
```

### UPDATE_BEACON
Usage:
```
UPDATE_BEACON
```

### VENDOR
Not understood yet.

Usage:
```
VENDOR cmd
```

### ERP_FLUSH
Usage:
```
ERP_FLUSH
```

### LOG_LEVEL
Usage:
```
LOG_LEVEL
```

### DRIVER_FLAGS
Usage:
```
DRIVER_FLAGS
```

### TERMINATE
Usage:
```
TERMINATE
```

### ACCEPT_ACL
Usage:
```
ACCEPT_ACL ADD_MAC mac_address
ACCEPT_ACL DEL_MAC mac_address
ACCEPT_ACL SHOW
ACCEPT_ACL CLEAR
```

### DENY_ACL
Usage:
```
DENY_ACL ADD_MAC mac_address
DENY_ACL DEL_MAC mac_address
DENY_ACL SHOW
DENY_ACL CLEAR
```

## iptables commands
```bash
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F  -t nat
iptables -F  -t mangle
iptables -F
iptables -X
iptables -A FORWARD -t filter --src 224.0.0.0/4 --dst 224.0.0.0/4 -j ACCEPT
iptables -A FORWARD -t filter -i br0 -j REJECT
iptables -A FORWARD -t filter -i br1 -j REJECT
iptables -A FORWARD -t filter -i br2 -j REJECT
iptables -A FORWARD -t filter -i br3 -j REJECT
iptables -A FORWARD -t filter -i br4 -j REJECT
iptables -A FORWARD -t filter -i br5 -j REJECT
iptables -A FORWARD -t filter -i br6 -j REJECT
iptables -A FORWARD -t filter -i br7 -j REJECT
iptables -A FORWARD -t filter -i br8 -j REJECT
iptables -A FORWARD -t filter -i br9 -j REJECT
iptables -A FORWARD -t filter -i br10 -j REJECT

iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 9 -t filter --src 10.0.7.157 --dst 10.0.8.191 -i br7 -o br8 -j ACCEPT
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 11 -t filter --src 10.0.8.191 --dst 10.0.7.157 -i br8 -o br7 -j ACCEPT

iptables -L FORWARD -t filter --line-numbers -n -v
iptables -D FORWARD 9 -t filter
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -D FORWARD 10 -t filter

iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 9 -t filter --src 10.0.7.157 --dst 0.0.0.0/0 -i br7 -o wlan3 -j ACCEPT
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 1 -t filter --src 0.0.0.0/0 --dst 10.0.7.157 -i wlan3 -o br7 -j ACCEPT
iptables -L POSTROUTING -t nat --line-numbers -n -v
iptables -I POSTROUTING 1 -t nat --src 10.0.7.157 --dst 0.0.0.0/0 -o wlan3 -j MASQUERADE

iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 12 -t filter --src 10.0.8.191 --dst 0.0.0.0/0 -i br8 -o wlan3 -j ACCEPT
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -L FORWARD -t filter --line-numbers -n -v
iptables -I FORWARD 1 -t filter --src 0.0.0.0/0 --dst 10.0.8.191 -i wlan3 -o br8 -j ACCEPT
iptables -L POSTROUTING -t nat --line-numbers -n -v
iptables -I POSTROUTING 1 -t nat --src 10.0.8.191 --dst 0.0.0.0/0 -o wlan3 -j MASQUERADE
```
