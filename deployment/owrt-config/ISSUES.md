# ISSUES

## Useful commands

### Print all listening ports on the server

```bash
netstat -tutlp
```

## DNS not working

See https://openwrt.org/docs/guide-user/base-system/dhcp_configuration#disabling_dns_role

It's possible that `port = 0` is set somewhere in `/etc/config/dhcp`
This will cause `dnsmasq` to disable `dns`.
