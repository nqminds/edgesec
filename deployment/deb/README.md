# Creating the .deb

## Creating Deb Template

```
debmake -t -p edgesec -u 0.9.9-alpha -r 1 --extra 4
```

## Creating Deb

### Build Environment

#### Podman

If you want to use podman (e.g. since you're using elementary OS), you can

Install .deb build dependencies, as well as the build depenencies for EDGESec (see README.md)

```bash
sudo apt install gnupg linux-headers-generic ubuntu-dev-tools apt-file -y
```

Replace `-j9` with how many threads you want to use.
This will automatically call `cmake` in the background.

```bash
debuild -us -uc -j9
```

- Add the `--no-pre-clean` to prevent `debuild` from recompiling everything.
  This saves a lot of time during testing.

#### PBuild

Install build dependencies

```bash
sudo apt install gnupg pbuilder fakechroot ubuntu-dev-tools apt-file -y
```

Then create a pbuild environment (basically a chroot jail).

We use `fakechroot fakeroot` to make this work in `podman`.

Replace `--distribution focal` with the OS you are using.

```bash
pbuilder create --debootstrapopts --variant=buildd --distribution focal
```
