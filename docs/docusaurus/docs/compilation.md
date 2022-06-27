---
slug: compilation
title: Compilation & Build
---

The codebase can be clone from the Github [repo](https://github.com/nqminds/edgesec).

## Dependencies

On Debian/Ubuntu, build dependencies are listed in the
[`debian/control`](https://github.com/nqminds/EDGESec/blob/main/debian/control) file.

You can use [`mk-build-deps`](https://manpages.ubuntu.com/manpages/focal/man1/mk-build-deps.1.html)
to automatically install these build-dependencies.

```bash
sudo apt install devscripts # install mk-build-depends
sudo mk-build-deps --install debian/control
```

## Compile & Build

Compiling EDGESec is done with CMake.

If you have CMake v3.22+, you can use the following `cmake-presets` to compile EDGESec:

```bash
cmake --preset linux # configure EDGESec for Linux
cmake --build --preset linux -j4 # build EDGESec for Linux using 4 threads
ctest --preset linux # test EDGESec for Linux
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

The configure stage will download some of the EDGESec dependencies, so this may take a while.

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

## Installation

You can use the following to also install files into `build/edgesec-dist`:

```bash
# Can do make and install in one step with
# `cmake --build build/ --target install -j4`
cmake --install build/
```

### Installing to custom location

Set `-DCMAKE_INSTALL_PREFIX=<YOUR-LOCATION-HERE>` to build for a different location:

```bash
cmake -B build/ -S . -DCMAKE_INSTALL_PREFIX=/tmp/example-build
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

## Testing

To compile the tests use:

```bash
cmake -B build/ -S . # configure CMAKE
cmake --build build/ -j4 # or make -j4
cmake --build build/ --target test -j4 # or `make test`
```

To run each test individually, the test binaries can be located in `./build/tests` folder.

## Developer Documentation

To compile the docs from `./build` folder:

```console
make doxydocs
```

See [`./docs`](./docs) for how to build the developer doxygen documentation website.
