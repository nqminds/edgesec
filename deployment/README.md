# EdgeSec Deployment

Deploying EdgeSec onto an entire device stack.

The following code uses Ubuntu 20.04.2 64-bit server edition on Raspberry Pi 4's with 8GB RAM.

As storage, we're currently planning on using
Kingston Canvas Select Plus microSDXC cards, with 256 GB storage.
(warning, this range of SD cards has much lower performance at 128 GB or less).

These claim to have 85 MB/s write speeds, with strong random RW performance
(unlike most SD cards, which only have strong sequential performance).

## Instructions

### Flashing Image

- [Ubuntu Raspberry Pi][1] page.
- [Raspberry Pi Ubuntu 20.04.2 64-bit Server Download][2]


  [1]: https://ubuntu.com/download/raspberry-
  [2]: https://cdimage.ubuntu.com/releases/20.04.2/release/ubuntu-20.04.2-preinstalled-server-arm64+raspi.img.xz

  Sha256sum:

  ```
  31884b07837099a5e819527af66848a9f4f92c1333e3ef0693d6d77af66d6832  ubuntu-20.04.2-preinstalled-server-arm64+raspi.img.xz
  ```

We recommend using Ether Electron to flash the SD card. It can be installed via:

```bash
sudo mkdir -p /usr/local/share/keyrings/
sudo wget https://dl.cloudsmith.io/public/balena/etcher/gpg.70528471AFF9A051.key -O /usr/local/share/keyrings/balena-etcher-gpg.70528471AFF9A051.key
```

Then add the following to `/etc/apt/sources.list.d/etcher.sources`:

```sources
Types: deb
URIs: https://dl.cloudsmith.io/public/balena/etcher/deb/ubuntu
Suites: focal
Components: main
Signed-By: /usr/local/share/keyrings/balena-etcher-gpg.70528471AFF9A051.key
```

Then finally, you can do:

```bash
sudo apt update && sudo apt install balena-etcher-electron -y
# start etcher electron
/opt/balenaEtcher/balena-etcher-electron.bin
```

You can then use `gnome-disks` to resize the flashed SD card, to use up all the space in the card:

```bash
gnome-disks
```

### Connecting to the Pi

You can then scan via `nmap -sV -p 22 192.168.1.*` to find devices on the local
network that have an open SSH port. One of them should be the Ubuntu Raspberry Pi.

The default login details are username `ubuntu` and password `ubuntu`.

After logging in, you can do the following:

- Install avahi-daemon, this lets you find the pi on the network by doing:
  `ping <hostname>.local`.

  ```bash
  sudo apt update && sudo apt install avahi-daemon -y
  ````

- Clone the EDGESec Repo.

  ```bash
  git clone --recurse-submodules --depth 1 https://github.com/nqminds/EDGESec.git --branch deployment
  ```

- Add admin SSH keys:

  ```bash
  cd ~/EDGESec/deployment/
  # add admin SSH keys (these must be FIDO2 keys!)
  cp ./ssh/authorized_keys ~/.ssh/authorized_keys
  ```
- Follow instructions in `first-boot`.
- Follow instruction in https://nqminds.github.io/edgesec-packages/ to install edgesec:

  ```bash
  # make a key store dir if it doesn't exist
  sudo mkdir -p /usr/local/share/keyrings
  # download our public key
  sudo wget https://nqminds.github.io/edgesec-packages/edgesec_rootkey_pub.gpg -O /usr/local/share/keyrings/edgesec_rootkey_pub.gpg
  # download our edgesec.sources file
  sudo wget https://nqminds.github.io/edgesec-packages/edgesec.sources -O /etc/apt/sources.list.d/edgesec.sources
  sudo apt update && sudo apt install edgesec
  ```
- Setup unattended updates.

  It should already be installed, you just need to edit and add the following line
  in `/etc/apt/apt.conf.d/50unattended-upgrades` under `Unattended-Upgrade::Allowed-Origins`.

  ```
  Unattended-Upgrade::Allowed-Origins {
    // edgesec
    "nqminds.github.io/edgesec-packages:";
  };
  ```

  This can be tested via doing a dry-run:

  ```bash
  sudo unattended-upgrades --dry-run --debug
  ```

## Generating FIDO2 SSH Keys

SSH keys can be generated that require using hardware security keys, using the FIDO2 protocol:

```bash
cmd=(ssh-keygen # use bash array so we can do multi-line comments
    -t ed25519-sk # ed25519-sk is the only SSH key type you should be using
    -C "$(whoami)@$(hostname)" # comment, make sure to identify your computer's name
    -O 'application=ssh:edgesec' # this is so your hardware key knows what you are signing for
)
"${cmd[@]}" # expand and run bash array
```

This effecitvely turns turns SSH logins into 2FA.
You need both the partial private key seed on your laptop, AND the FIDO2 security key
to SSH into the system.

You can add more factors of authentication by requiring a PIN on your FIDO2 key,
see the [`-O verify-required` option](https://man.openbsd.org/ssh-keygen.1#verify-required).
(FIDO2 keys with a built-in screen are keylogger proof).
