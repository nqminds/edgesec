---
slug: running
title: Running
---

To run `edgesec` tool with the configuration file `dev-config.ini` located in `./build` folder use:

```console
./build/src/edgesec -c ./build/dev-config.ini
```

To enable verbose debug mode use:

```console
./build/src/edgesec -c ./build/dev-config.ini -ddddd
```

The configuration file `config.ini` has been setup to work by default only when:

- running on Raspberry Pi (e.g. `wlan1` is the name of Wifi USB AP and `eth0` is the ethernet port)
- running after `make install` has been run

##### Running edgesec tool with debug info and master password `12345` (verbose)

```bash
sudo CRYPT_KEY=12345 ./src/edgesec -c config.ini -ddddddddd
```

##### Running capsrv tool with syncing of `br10` interface to `localhost:8512` with grpc CA located in `/cert/CA/CA.pem` and data stored in `./db` folder (verbose)

```bash
sudo ./src/capsrv -i br10 -t 10 -n 10 -y default -w -s -p ./db -a localhost -o 8512 -k ./cert/CA/CA.pem -r 1000000,100 -dddddddddd
```

##### Running capsrv in cleaning mode only (verbose)

Scans `./db/pcap-meta.sqlite` until pcap capture has reached `-b 20971520` KiB (aka 20 GiB).

```bash
./src/capsrv -p ./db -b 20971520 -dddddddd
```
