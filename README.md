# EDGESec
[![C/C++ CI](https://github.com/nqminds/EDGESec/workflows/C/C++%20CI/badge.svg?branch=main)](https://github.com/nqminds/EDGESec/actions?query=workflow%3A%22Github+Pages%22)

## Build

Compiling EDGESec is done with CMake.

### Installing Dependencies

On Ubuntu, we need a C compiler, CMake, Doxygen, and libnl libraries:

```console
sudo apt update
sudo apt install cmake build-essentials doxygen libnl-genl-3-dev libnl-route-3-dev graphviz
```

### Compile

```
mkdir -p build/
cd build/
cmake ..
cmake --build -j2 .. # replace 2 with number of threads to use for building
```

After succesful compilation the binary will be located in ```./build/src/edgesec```.

## Running

To run ```edgesec``` tool with a configuration file ```config.ini``` located in ```./build``` folder use:
```
./build/src/edgesec -c ./build/config.ini
```

To enable verbose debug mode use:
```
./build/src/edgesec -c ./build/config.ini -ddddd
```

## Developer Documentation

See [`./docs`](./docs) for how to build the developer doxygen documentation website.

## Commands
[Hostapd and supervisor commands](./docs/COMMANDS.md)

## ISSUES
[Installation and compilation issues](./docs/ISSUES.md)
