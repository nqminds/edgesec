---
slug: commands
title: Control Commands
---

## EDGESec Commands

### PING_SUPERVISOR

Usage:

```
PING_SUPERVISOR
```

### ACCEPT_MAC

Usage:

```
ACCEPT_MAC mac_address vlanid
```

### DENY_MAC

Usage:

```
DENY_MAC mac_address
```

### ADD_NAT

Usage:

```
ADD_NAT mac_address
```

### REMOVE_NAT

Usage:

```
REMOVE_NAT mac_address
```

### ASSIGN_PSK

Usage:

```
ASSIGN_PSK mac_address password
```

### GET_MAP

Usage:

```
GET_MAP mac_address
```

### GET_ALL

Usage:

```
GET_ALL
```

### ADD_BRIDGE

Usage:

```
ADD_BRIDGE mac_address_src mac_address_dst
```

### REMOVE_BRIDGE

Usage:

```
REMOVE_BRIDGE mac_address_src mac_address_dst
```

### CLEAR_BRIDGE

Usage:

```
CLEAR_BRIDGE mac_address
```

### GET_BRIDGES

Usage:

```
GET_BRIDGES
```

### REGISTER_TICKET

Usage:

```
REGISTER_TICKET mac_address device_label vlanid
```

### CLEAR_PSK

Usage:

```
CLEAR_PSK mac_address
```

### PUT_CRYPT

Usage:

```
PUT_CRYPT key_id value[base64]
```

### GET_CRYPT

Usage:

```
GET_CRYPT key_id
```

### GEN_RANDKEY

Usage:

```
GEN_RANDKEY key_id key_size[bytes]
```

### GEN_PRIVKEY

Usage:

```
GEN_PRIVKEY key_id key_size[bytes]
```

### GEN_PUBKEY

Usage:

```
GEN_PUBKEY public_key_id private_key_id
```

### GEN_CERT

Usage:

```
GEN_CERT certificate_kid private_key_id common_name
```

### ENCRYPT_BLOB

Usage:

```
ENCRYPT_BLOB key_id iv_id blob[base64]
```

### DECRYPT_BLOB

Usage:

```
DECRYPT_BLOB key_id iv_id blob[base64]
```

### SIGN_BLOB

Usage:

```
SIGN_BLOB key_id blob[base64]
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

### ATTACH

Usage:

```
ATTACH
```

### DETTACH

Usage:

```
DETTACH
```
