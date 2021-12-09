---
slug: running
title: Running
---

To run ```edgesec``` tool with the configuration file ```dev-config.ini``` located in ```./build``` folder use:

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
sudo ./src/edgesec -c config.ini -s 12345 -ddddddddd
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

Running restsrv on port `8513` with TLS certificate generation for `localhost` (verbose):

```bash
sudo ./src/restsrv -s /tmp/edgesec-domain-server -p 8513 -z 32 -c localhost -t -dddddddd
```

##### Running revclient to `localhost:8514` with grpc CA located in `/cert/CA/CA.pem` and data stored in `./db` folder (verbose):

Normally, you'd want to connect to a cloud server, but for testing, we can use `localhost`. Port and cert should match parameters passed to `revsrv`:

```bash
sudo ./src/revclient -f ./db -a localhost -p 8514 -c ./cert/CA/CA.pem -dddddddd
```

##### Running revclient to `localhost:8514` without grpc CA and data stored in `./db` folder:

```bash
sudo ./src/revclient -f ./db -a localhost -p 8514
```

##### Cloud server - Running revsrv on port `8514` (verbose):

The following programs are designed to run on a publically accesible server, that an EDGESec toolset can connect to.

The GRPC certificate authority (`-a <example.CA.pem>`) MUST match the certificate authority passed to `revclient` on the EDGEsec device.

Make sure that your server SSL certificate has the appropriate hostname (e.g. `localhost`, or `edgesec-1.nqm-1.com`).

```bash
sudo ./revsrv -p 8514 -a /etc/edgesec/CA/CA.pem -c /etc/edgesec/revsrv/server.crt -k /etc/edgesec/revsrv/server.key -dddddd
```
