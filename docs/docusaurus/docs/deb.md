---
slug: deb
title: Creating a .deb
---

## Using GitHub Actions (recommended)

1. Update [`debian/changelog`](https://github.com/nqminds/EDGESec/debian/changelog) and make a new version.
2. [Create a new GitHub Release](https://github.com/nqminds/EDGESec/releases/new),
  using the branch where you pushed the updated changelog.
3. After creating a Release (and when it's **NOT** a draft),
  the [create-debs.yml](https://github.com/nqminds/EDGESec/actions/workflows/create-debs.yml)
  will automatically compile the `.deb` files, and upload them as
  part of the Release you made.

## Build Environment

The recommended way of building a `.deb` is using the software `pbuilder`.

This will automatically run `sudo apt install [...<dependencies>]`
in a `chroot` environment.

However, this does mean you need `sudo` access, even though you are only
installing into a `chroot` environment.

Additionally, you also need access to `chroot`, so `pbuilder` does not work
in a container like `docker`/`podman`.

### PBuild

Install build dependencies:

```bash
sudo apt install gnupg pbuilder debhelper -y
```

Then create a pbuild environment (basically a chroot jail).
This lets us install apt packages without affecting our OS.

Replace `--distribution focal` with the OS you are using.

```bash
sudo pbuilder create --debootstrapopts --variant=buildd --distribution focal
```

Next, you must have `USENETWORK=yes` enabled in your `/etc/pbuilderrc` file.
This is so that cmake can download files while building.

```ini
# Enable network access, since `cmake` downloads dependencies
USENETWORK=yes
```

Finally, you can build the `.deb` file with:

```bash
pdebuild --debbuildopts "-us -uc"
```

The meaning of the options are:
- `-debbuildopts <debbuild_opts>`: Options to pass to `debbuild`. See `debbuild` options above in the [**Podman**](#podman) section.
  - `"-us -uc"` means do not sign the source package and `.changes` file.

By default, the `.deb` file will be located in `/var/cache/pbuilder/result/`.

### Cross-compiling

First of all, install `pbuilder`, which automatically downloads dependencies
and does the cross-compiling for you.

```bash
sudo apt install gnupg pbuilder debhelper -y
```

Then, edit `/etc/pbuilderrc` and enable the following settings:

```ini
# Enable network access, since `cmake` downloads dependencies
USENETWORK=yes
# Faster than default, and is requried if we want to do cross-compiling
PBUILDERSATISFYDEPENDSCMD="/usr/lib/pbuilder/pbuilder-satisfydepends-apt"
```

First of all, we need to overwrite our apt-sources list.
Ubuntu places x86 sources seperately from ARM sources, so we need
to do some jiggarypokery to get it working.

Otherwise, it's just the same command as in [PBuild](#pbuild).

```bash
OTHER_MIRROR_LIST=(
  "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports focal main universe"
  # Ubuntu splits up amd64 and arm64 repos
  "deb [arch=amd64] http://gb.archive.ubuntu.com/ubuntu focal main universe"
)
OTHER_MIRROR=$(IFS='|' ; echo "${OTHER_MIRROR_LIST[*]}")
pdebuild --debbuildopts "-us -uc" -- --override-config --distribution focal --mirror "" --othermirror "$OTHER_MIRROR" --host-arch arm64
```

- `-- ...`: Options to pass to `pbuilder`:
  - `--host-arch arm64`: Cross-compile for the `arm64` architecture.
  - `--override-config`: Needed to regenerate `apt` settings, since we're setting `--othermirror`
  - `--mirror ""`: Leave blank, since we need to specify `[arch=xxx]` in `--othermirror`.
  - `--othermirror "$OTHER_MIRROR"`:
    The deb `sources.list` entries for both `arm64` (host) and `amd64` (build).
  - `--distribution focal`: Needed since we're regenerating `apt` settings.

By default, the `.deb` file will be located in `/var/cache/pbuilder/result/`.

### Podman

If you want to use podman
(e.g. since you're using elementary OS, or `pbuilder` doesn't work since you don't have `chroot` support),
you can use `debuild` manually.

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

## Editing the deb

- Beware of dependencies!
  The `Depends: ${shlibs:Depends}` line in `debian/control` means we automatically
  scan for shared libs.

  However, since we bundle in some shared libs, we must ignore these in `debian/control`,
  using the `-l` flag to `dh_shlibdeps`.
  This will tell `dh_shlibdeps` that a folder is our own private shared libs folder.
- Build dependencies:
  - If we use `git`, make sure you also add `ca-certificates`, otherwise you'll get
    invalid certificate errors when doing git clones with `https`.
- Creating a new version of the `.deb`:
  - To create a new version number for the `.deb`, add a new entry to `debian/changelog`
    with the version you want, then rebuild the `.deb`.
