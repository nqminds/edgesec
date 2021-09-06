# EDGESec
[![C/C++ CI](https://github.com/nqminds/EDGESec/workflows/C/C++%20CI/badge.svg?branch=main)](https://github.com/nqminds/EDGESec/actions?query=workflow%3A%22Github+Pages%22)

## Build
### Installing Dependencies

On Ubuntu, we need a C compiler, CMake, Doxygen, and libnl libraries:

```console
sudo apt update
apt_dependencies=(
    cmake # build-tool
    doxygen texinfo graphviz # documentation
    build-essential # C and C++ compilers
    libnl-genl-3-dev libnl-route-3-dev # netlink dependencies
    automake # required by libmicrohttpd for some reason?
    autoconf # required by compile_sqlite.sh
    libtool-bin # required by autoconf somewhere
    pkg-config # seems to be required by nDPI
    libjson-c-dev # mystery requirement
    protobuf-compiler
    flex bison
)
sudo apt install -y "${apt_dependencies[@]}"
```

To install grpc dependencies:
```console
cd lib/
sudo ./compile_grpc_deps.sh
```

### Compile
Compiling EDGESec is done with CMake. First create the makefiles by using the following commands:
```console
mkdir -p build/
cd build/
cmake ..
```
For parallel builds use:
```console
cmake -j n ..
```
where ```n``` is the number of cores.

Second, to compile the ```edgesec``` tool and the tests use:
```console
make all
```

After succesful compilation the binary will be located in ```./build/src``` folder.

## Running

To run ```edgesec``` tool with a configuration file ```config.ini``` located in ```./build``` folder use:
```console
./build/src/edgesec -c ./build/config.ini
```

To enable verbose debug mode use:
```console
./build/src/edgesec -c ./build/config.ini -ddddd
```

## Testing
To compile the tests use:
```console
cd build/
rm CMakeCache.txt
cmake -DBUILD_TEST=ON ../
make
make test
```

To run each test individually the test binaries can be located in ```./build/tests``` folder.

## Developer Documentation

To compile the docs from ```./build``` folder:
```console
make doxydocs
```

See [`./docs`](./docs) for how to build the developer doxygen documentation website.

## Config
[Configuration file structure](./docs/CONFIG.md)

## Commands
[Hostapd and supervisor commands](./docs/COMMANDS.md)

## ISSUES
[Installation and compilation issues](./docs/ISSUES.md)
