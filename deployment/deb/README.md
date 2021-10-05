# Creating the .deb

## Creating Deb

### Build Environment

#### Podman

If you want to use podman (e.g. since you're using elementary OS), you can setup a new image

Install .deb build dependencies, as well as the build depenencies for EDGESec (see README.md)

```bash
sudo apt install gnupg linux-headers-generic ubuntu-dev-tools apt-file -y
```

This will automatically call `cmake` in the background, using multiple threads (e.g. no need for `j6`)

```bash
debuild -us -uc
```

- Add the `--no-pre-clean` to prevent `debuild` from recompiling everything.
  This saves a lot of time during testing.
- `-us -uc` means do not sign the source package and `.changes` file.

Now the deb should exist in the folder above this folder, e.g. `cd ..`.

#### PBuild

**WARNING** NOT FULLY TESTED YET

Install build dependencies

```bash
sudo apt install gnupg pbuilder fakechroot ubuntu-dev-tools apt-file -y
```

Then create a pbuild environment (basically a chroot jail).
This lets us install apt packages without affecting our OS.

Replace `--distribution focal` with the OS you are using.

```bash
sudo pbuilder create --debootstrapopts --variant=buildd --distribution focal
```

Finally, you can build the `.deb` file with:

```bash
pdebuild --debbuildopts -us -uc
```

The meaning of the options are:
- `-debbuildopts ...`: Options to pass to `debbuild`. See `debbuild` options above in the [**Podman**](#podman) section.
  - `-us -uc` means do not sign the source package and `.changes` file.

#### Cross-compiling

Here? https://wiki.debian.org/Multiarch/Implementation

## Editing the deb

- Beware of dependencies!
  The `Depends: ${shlibs:Depends}` line in `debian/control` means we automatically
  scan for shared libs.

  However, since we bundle in some shared libs, we must ignore these in `debian/control`,
  using the `-l` flag to `dh_shlibdeps`.
  This will tell `dh_shlibdeps` that a folder is our own private shared libs folder.
