# Docker containers for cross compile

### Podman

The following commands also work using the `podman` container runtime (recommended on Linux):

```console
alias docker=podman
```

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

Execute a command ```<cmd>``` in the currrent folder that is mounted to the container folder `/opt/EDGESec` use:

```console
# In the ./deployment/containers/ folder
docker run --rm --volume "$PWD":/opt/EDGESec --workdir /opt/EDGESec openwrt <cmd>
```
where `openwrt` is the container name from Step 2.

### Compiling EDGESec

To compile EDGESec in the docker container, go back to the root of the Git Repo, and run.

```console
# in root of git repo (where the `CMakePresets.json` file is)
docker run --rm --volume "$PWD":/opt/EDGESec --workdir /opt/EDGESec openwrt cmake --preset openwrt/default
```

To compile using cmake (on 4 cores)

```console
docker run --rm --volume "$PWD":/opt/EDGESec --workdir /opt/EDGESec openwrt cmake --build --preset openwrt/default  -j4
```

Afterwards, you'll find the compiled binaries in the `build/openwrt/default` folder.
