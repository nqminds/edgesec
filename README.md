# edgesec

[![Build Debian Packages](https://github.com/nqminds/edgesec/actions/workflows/create-debs.yml/badge.svg)](https://github.com/nqminds/edgesec/actions/workflows/create-debs.yml) ![Release](https://badgen.net/badge/release/0.0.8/blue?icon=color)

edgesec defines a new architecture and toolset for edge based routers addressing
fundamental security weaknesses that impact current IP and IoT router implementations.

For more information, please see the edgesec website: [https://edgesec.info](https://edgesec.info)

## Dependencies

On Debian/Ubuntu, build dependencies are listed in the
[`debian/control`](https://github.com/nqminds/edgesec/blob/main/debian/control) file.

You can use [`mk-build-deps`](https://manpages.ubuntu.com/manpages/focal/man1/mk-build-deps.1.html)
to automatically install these build-dependencies.

```bash
sudo apt install devscripts # install mk-build-depends
sudo mk-build-deps --install debian/control
```

## Compile & Build

Compiling edgesec is done with CMake.


If you have CMake v3.22+, you can use the following `cmake-presets` to compile edgesec:

```bash
cmake --preset linux # configure edgesec for Linux
cmake --build --preset linux -j4 # build edgesec for Linux using 4 threads
ctest --preset linux # test edgesec for Linux
```

A useful one-liner is the following, which given a preset, automatically
configures, compiles (using all cores, but `nice -n19` for lower CPU priority),
tests (if a test config exists), then installs into the `./tmp` folder.

```bash
export PRESET=linux; cmake --preset "$PRESET" && nice -n19 cmake --build --preset "$PRESET" -j=$(nproc) && ( ctest --list-presets | grep "\"$PRESET\"" ) && ctest --preset "$PRESET"; cmake --install "./build/$PRESET" --prefix "./tmp/$PRESET"
```

For older versions of CMake, or for manual configuration, please see the next headings for more details.

### Configure

Configure `cmake` in the `build/` directory by running the following:

```bash
# or for old versions of cmake, do: mkdir build/ && cd build/ && cmake ..
cmake -S . -B build
```

The configure stage will download some of the edgesec dependencies, so this may take a while.

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
