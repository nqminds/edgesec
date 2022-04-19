# REFERENCES

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

## Aricles
1. [Google TSPI](https://github.com/google/go-tspi)
2. [Trusted Grub](https://github.com/Rohde-Schwarz/TrustedGRUB2)
3. [TrouSerS](http://trousers.sourceforge.net/)
4. [IBM SW TPM2](https://sourceforge.net/projects/ibmswtpm2/)
5. [Software TPM](https://github.com/stefanberger/swtpm)
6. [Kernel INtegrity System](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/enhancing-security-with-the-kernel-integrity-subsystem_managing-monitoring-and-updating-the-kernel)
7. [Kernel Key Retention](https://www.kernel.org/doc/html/v4.18/security/keys/core.html)
8. [Linux Integrity Measurement Architecture](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture)
9. [IMA](https://sourceforge.net/p/linux-ima/wiki/Home/)
