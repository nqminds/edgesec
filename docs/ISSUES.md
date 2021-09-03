# libmnl-1.0.4
## aclocal-1.15: command not found
```console
cd lib/libmnl-1.0.4
autoreconf -f -i
```

# "Predictable names" for WiFi interfaces
https://wiki.debian.org/NetworkInterfaceNames#legacy

The scheme detailed above is the new standard default, but there's also a canonical way of overriding the default: you can use .link files to set up naming policies to suit your needs. Thus for instance if you have two PCs each of which has only a single wireless card, but one calls it wlp0s1 and the other wlp1s0, you can arrange for them both to use the name wifi0 to simplify sharing firewall configurations. For details see systemd.link(5).

Here's a relatively futureproof "manual" version of the example given above:

```
 #/etc/systemd/network/10-persistent-net.link
 [Match]
 MACAddress=01:23:45:67:89:ab

 [Link]
 Name=lan0
```

Note: per systemd.link(5), you shouldn't use a name that the kernel might use for another interface (for example "eth0").

It is also possible to reorganize the naming policy by overriding /lib/systemd/network/99-default.link, for instance to insist that all network interfaces are named purely by MAC address:

```
 #/etc/systemd/network/99-default.link
 [Match]
 OriginalName=*

 [Link]
 NamePolicy=mac
 MACAddressPolicy=persistent
```

The folder ```./scripts``` contains the ```predictable_wifi_name.sh``` script to automaticall create the above lik file.

Usage:
```console
sudo ./scripts/predictable_wifi_name.sh source_if_name destination_fi_name
```

# Stop wpa_supplicant listenning on WiFi interfaces (Raspberry Pi case)
Disable the entire wap_supplicant add the below line to ```/etc/dhcpcd.conf```:
```
nohook wpa_supplicant
```

Disable only for a particular wifi interface ```wlanx``` add the below line to ```/etc/dhcpcd.conf```:
```
denyinterfaces wlanx
```

# iptables commands
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

# References
1. [Google TSPI](https://github.com/google/go-tspi)
2. [Trusted Grub](https://github.com/Rohde-Schwarz/TrustedGRUB2)
3. [TrouSerS](http://trousers.sourceforge.net/)
4. [IBM SW TPM2](https://sourceforge.net/projects/ibmswtpm2/)
5. [Software TPM](https://github.com/stefanberger/swtpm)
6. [Kernel INtegrity System](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/enhancing-security-with-the-kernel-integrity-subsystem_managing-monitoring-and-updating-the-kernel)
7. [Kernel Key Retention](https://www.kernel.org/doc/html/v4.18/security/keys/core.html)
8. [Linux Integrity Measurement Architecture](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture)
9. [IMA](https://sourceforge.net/p/linux-ima/wiki/Home/)