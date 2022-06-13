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
