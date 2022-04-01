# Docker containers for cross compile

## Build

### Step 1
In `config.mak` change the `TARGET` key to the desired architecture (see details [https://github.com/richfelker/musl-cross-make](https://github.com/richfelker/musl-cross-make)):
- aarch64[_be]-linux-musl
- arm[eb]-linux-musleabi[hf]
- i*86-linux-musl
- microblaze[el]-linux-musl
- mips-linux-musl
- mips[el]-linux-musl[sf]
- mips64[el]-linux-musl[n32][sf]
- powerpc-linux-musl[sf]
- powerpc64[le]-linux-musl
- riscv64-linux-musl
- s390x-linux-musl
- sh*[eb]-linux-musl[fdpic][sf]
- x86_64-linux-musl[x32]

Set `MUSL_VER` key to the platform MUSL library version. Use
```console
ldd --version
```
to find the MUSL library version `x.y.z`.

### Step 2
Using the container name `openwrt` build the docker container using the command:
```console
docker build -t openwrt .
```

## Run
Execute a command ```cmd``` in the currrent folder that is mounted to the container folder `/opt/EDGESec` use:
```console
docker run --rm -v "$PWD":/opt/EDGESec -w /opt/EDGESec openwrt cmd 
```
where `openwrt` is the container name from Step 2.

### Examples
To run the cmake build for a cmake buidl folder
```console
docker run --rm -v "$PWD":/opt/EDGESec -w /opt/EDGESec openwrt cmake -B build/ -S .
```

To compile using cmake (on 4 cores)
```console
docker run --rm -v "$PWD":/opt/EDGESec -w /opt/EDGESec openwrt cmake --build build/ -j4
```
