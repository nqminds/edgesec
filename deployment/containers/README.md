# Docker containers for cross compile

## Build

In `config.mak` change the `TARGET` to the desired architecture and `MUSL_VER` to the platform MUSL library version. Use `ldd --version``` to find teh MUSL library version.

Using the container name `openwrt` we can build the docker container using the command:
```bash
docker build -t openwrt .
```

## Run
To mount the current folder to container folder `/opt/EDGESec` and execute a command `cmd`:
```bash
docker run --rm -v "$PWD":/opt/EDGESec -w /opt/EDGESec openwrt cmd 
```
where `openwrt` is the container name.