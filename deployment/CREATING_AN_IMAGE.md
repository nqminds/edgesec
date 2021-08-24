# Creating the EDGESEC Operating System Image from Scratch

## Initial image creation and SSH

Firstly, we start off with an Ubuntu 20.04 64-bit Raspberry Pi image.

- [Ubuntu Raspberry Pi][1] page.
- [Raspberry Pi Ubuntu 20.04.2 64-bit Server Download][2]


  [1]: https://ubuntu.com/download/raspberry-
  [2]: https://cdimage.ubuntu.com/releases/20.04.2/release/ubuntu-20.04.2-preinstalled-server-arm64+raspi.img.xz

  Sha256sum:

  ```
  31884b07837099a5e819527af66848a9f4f92c1333e3ef0693d6d77af66d6832  ubuntu-20.04.2-preinstalled-server-arm64+raspi.img.xz
  ```

On Ubuntu, you can just double-click on the `.img.xz` to write it to an SD card.
Otherwise, you can use a software like
[Balena's Etcher Electron](https://github.com/balena-io/etcher).


If you are going to use WiFi, modify the `/etc/wpa_supplicant` file on the SD
card.

After turning on the Raspberry Pi,
you can then scan via `nmap -sV -p 22 192.168.1.*` to find devices on the local
network that have an open SSH port. One of them should be the Ubuntu Raspberry Pi.

The default login details are username `ubuntu` and password `ubuntu`.

## SSH Server setup

Copy `./ssh/authoirzed_keys` to `~/.ssh/authorized_keys`.
This will allow us to SSH in without a password,
preventing man-in-the-middle and dictionary attacks.

## Reverse SSH setup
