# [edgesec](https://edgesec.info)

[![GitHub release (latest stable SemVer)](https://img.shields.io/github/v/release/nqminds/edgesec?label=stable&logo=github&sort=semver)](https://github.com/nqminds/edgesec/releases)
[![Build Debian Packages](https://github.com/nqminds/edgesec/actions/workflows/create-debs.yml/badge.svg)](https://github.com/nqminds/edgesec/actions/workflows/create-debs.yml)
[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/nqminds/edgesec?include_prereleases&label=latest&logo=github&sort=semver)](https://github.com/nqminds/edgesec/releases)
[![GitHub license](https://img.shields.io/github/license/nqminds/edgesec)](https://github.com/nqminds/edgesec/blob/main/LICENSE)
[![Codecov Code Coverage](https://codecov.io/gh/nqminds/edgesec/branch/main/graph/badge.svg)](https://codecov.io/gh/nqminds/edgesec)
[![Documented with Doxygen](https://img.shields.io/badge/docs-Doxygen-blue.svg?foo&bar)](https://edgesec.info/doxygen/)
[![GitHub Pages](https://github.com/nqminds/edgesec/actions/workflows/pages.yml/badge.svg)](https://github.com/nqminds/edgesec/actions/workflows/pages.yml)
![CMake](https://img.shields.io/badge/CMake-%23008FBA.svg?logo=cmake&logoColor=white)
![C11](https://img.shields.io/badge/C11-informational.svg?logo=c)
[![code style: llvm](https://img.shields.io/badge/code%20style-LLVM-green?logo=llvm&color=2b617a)](https://llvm.org/docs/CodingStandards.html)
[![OpenWRT package feed](https://img.shields.io/badge/OpenWRT%20Package%20Feed-%23002B49.svg?logo=OpenWrt&logoColor=white)](https://github.com/nqminds/manysecured-openwrt-packages)

edgesec defines a new architecture and toolset for edge based routers addressing
fundamental security weaknesses that impact current IP and IoT router implementations.

For more information, please see the edgesec website: [https://edgesec.info](https://edgesec.info)

## Dependencies

On Debian/Ubuntu, build dependencies are listed in the
[`debian/control`](https://github.com/nqminds/edgesec/blob/main/debian/control) file.

You can use [`mk-build-deps`](https://manpages.ubuntu.com/manpages/focal/man1/mk-build-deps.1.html)
to automatically install these build-dependencies.

```bash
sudo apt install devscripts equivs # install mk-build-depends
sudo mk-build-deps --install debian/control
```

On other OSes, you can try to find dependencies yourself, or you can run the
instructions in a new Ubuntu Docker or Podman container:

```bash
# in root of git repo (where the `CMakePresets.json` file is)
docker run --rm -it --volume "$PWD":/opt/EDGESec --workdir /opt/EDGESec ubuntu:jammy bash
# then run the Debian/Ubuntu dependencies setup instructions
```

## Compile & Build

Compiling edgesec is done with CMake.


If you have CMake v3.22+, you can use the following `cmake-presets` to compile edgesec:

```bash
cmake --list-presets # list all available presets
cmake --preset linux # configure edgesec for Linux
cmake --build --preset linux -j4 # build edgesec for Linux using 4 threads
ctest --preset linux # test edgesec for Linux
```

A useful one-liner (i.e. for `git rebase`) is the following, which given a preset, automatically
configures, compiles (using all cores, but `nice -n19` for lower CPU priority),
tests (if a test config exists), then installs into the `./tmp` folder.

```bash
export PRESET=linux && cmake --preset "$PRESET" && nice -n19 cmake --build --preset "$PRESET" -j=$(nproc) && { if ctest --list-presets | grep "\"$PRESET\""; then ctest --preset "$PRESET" --output-on-failure -j=$(nproc); fi } && cmake --install "./build/$PRESET" --prefix "./tmp/$PRESET"
```

For older versions of CMake, or for manual configuration, please see the next headings for more details.

### Configure

Configure `cmake` in the `build/` directory by running the following:

```bash
# or for old versions of cmake, do: mkdir build/ && cd build/ && cmake ..
cmake -S . -B build
```

The configure stage will download some of the edgesec dependencies, so this may take a while.

#### Configure for cross-compiling

To cross-compile edgesec, pass CMake a
[cmake-toolchain file](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html).

For example:

```bash
cmake -S . -B build --toolchain ./CMakeModules/CMakeToolchains/openwrt-ath79-generic.cmake
```

In [`./CMakeModules/CMakeToolchains`](./CMakeModules/CMakeToolchains), we have
some example toolchains that automatically download the OpenWRT SDK to cross-compile
for specific OpenWRT SDK versions.

You can also make a new preset in the [`CMakePresets.json`](./CMakePresets.json)
file that points to this toolchain.

#### Configure for OpenWRT

For production uses of edgesec, we recommend using the edgesec OpenWRT package
feed at https://github.com/nqminds/manysecured-openwrt-packages

It comes with an `/etc/init.d/edgesec` script that can be used to automatically
run edgesec on startup.

Additionally, this package allows easy installation/uninstallation of edgesec.

### Building

To build, you can then run:

```bash
# or for old versions of cmake, do: cd build/ && make
cmake --build build/
```

or to built on multiple core run:

```bash
cmake --build build/ -j4
```

`-j4` means 4 jobs/threads, replace `4` with the amount of cores you want to use, equivalent to `make -j4`.

After succesful compilation the binary will be located in `./build/src` folder.

## Running

To run `edgesec` tool with the configuration file `dev-config.ini` located in `./build` folder use:

```bash
./build/src/edgesec -c ./build/dev-config.ini
```

To enable verbose debug mode use:

```bash
./build/src/edgesec -c ./build/dev-config.ini -ddddd
```

## Testing

To compile the tests use:

```bash
cmake -B build/ -S . # configure CMAKE
cmake --build build/ -j4 # or make -j4
cmake --build build/ --target test -j4 # or 'make test'
```

To run each test individually, the test binaries can be located in `./build/tests` folder.

## Developer Documentation

To compile the docs from `./build` folder:

```bash
make doxydocs
```

See [`./docs`](./docs) for how to build the developer doxygen documentation website.
