# Commands
### Create interface
```console
ip link add name br0 type bridge
ip addr add 10.0.4.1/24 brd 10.0.4.255 dev br0
ip link set dev br0 up
```
