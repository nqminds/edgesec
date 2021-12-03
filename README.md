# EDGESec
[![C/C++ CI](https://github.com/nqminds/EDGESec/workflows/C/C++%20CI/badge.svg?branch=main)](https://github.com/nqminds/EDGESec/actions?query=workflow%3A%22Github+Pages%22)

### Installing Dependencies

On Ubuntu, we need a C compiler, CMake, Doxygen, and libnl libraries:

```bash
sudo apt update
build_dependencies=(
    cmake # build-tool
    git # required to download dependencies
    ca-certificates # required for git+https downloads
    doxygen texinfo graphviz # documentation
    build-essential # C and C++ compilers
    libnl-genl-3-dev libnl-route-3-dev # netlink dependencies
    automake # required by libmicrohttpd for some reason?
    autopoint gettext # required by libuuid
    autoconf # required by compile_sqlite.sh
    libtool-bin # required by autoconf somewhere
    pkg-config # seems to be required by nDPI
    libjson-c-dev # mystery requirement
    flex bison # required by pcap
    libgnutls28-dev # required by libmicrohttpd
    libssl-dev # required by hostapd only. GRPC uses own version, and we compile OpenSSL 3 for EDGESec
    protobuf-compiler-grpc libprotobuf-dev libgrpc++-dev # GRPC, can be removed if -DBUILD_GRPC_LIB=ON
    libcmocka-dev # cmocka, can be removed if -DBUILD_CMOCKA_LIB=ON
    libmnl-dev # libmnl, can be removed if -DBUILD_LIBMNL_LIB=ON
)
runtime_dependencies=(
    dnsmasq
    jq # required by predictable wifi name script
)
sudo apt install -y "${build_dependencies[@]}" "${runtime_dependencies[@]}"
```

### Compile & Build

Compiling EDGESec is done with CMake.

First, configure `cmake` in the `build/` directory by running the following.
```bash
mkdir build && cd build && cmake ../
```

Setting `-DLIB_MAKEFLAGS="--jobs=$(nproc)"` will mean that while compiling library dependencies,
`make` commands will run using all CPU cores, greatly speeding this building (set a lower number if you have less RAM).

```bash
cmake -B build/ -S . -DLIB_MAKEFLAGS="--jobs=$(nproc)"
```

To build, you can then run:
```bash
make
```
or to built on multiple core run:

```bash
cmake --build build/ -j4
```
`-j4` means 4 jobs/threads, replace `4` with the amount of cores you want to use, equivalent to `make -j4`.

After succesful compilation the binary will be located in ```./build/src``` folder.

### Installation

You can use the following to also install files into `build/edgesec-dist`:

```bash
# Can do make and install in one step with
# `cmake --build build/ --target install -j4`
cmake --install build/
```

#### Installing to custom location

Set `-DCMAKE_INSTALL_PREFIX=<YOUR-LOCATION-HERE>` to build for a different location:

```bash
MAKEFLAGS="--jobs=$(nproc)" cmake -B build/ -S . -DCMAKE_INSTALL_PREFIX=/tmp/example-build
cmake --build build/ --target install -j4
```
This will also automatically update `config.ini` to have all paths point to the installed location. You can also use the following to install to a different location than the one you built for.

```bash
# Will update config.ini, but will not update RPATHS!!!
cmake --install build/ --prefix <new-location>
```

This will not update the `RPATHs` (since they have to be known at compile time).
However, as we use relative `RPATHs`, as long as you don't change the folder structure,
it will be fine.

Please configure cmake with `-DCMAKE_INSTALL_PREFIX` and recompile if you want to change the RPATH.

## Running

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

## Testing

To compile the tests use:

```bash
cmake -B build/ -S . # configure CMAKE
cmake --build build/ -j4 # or make -j4
cmake --build build/ --target test -j4 # or `make test`
```

To run each test individually, the test binaries can be located in ```./build/tests``` folder.

## Developer Documentation

To compile the docs from ```./build``` folder:

```console
make doxydocs
```

See [`./docs`](./docs) for how to build the developer doxygen documentation website.

## Building the Debian package

Instructions to create `.deb` file are located in
[`./docs/CREATING_A_DEB.md`](./docs/CREATING_A_DEB.md).

## Config
[Configuration file structure](./docs/CONFIG.md)

## Commands
[Hostapd and supervisor commands](./docs/COMMANDS.md)

## ISSUES
[Installation and compilation issues](./docs/ISSUES.md)
