# First Boot setup

Instructions adapted from: https://github.com/nqminds/nqm-iot-hub-industrial/tree/master/installing_ubuntu/disk-image#make-os-initialize-on-next-boot

`nouns.list` from https://raw.githubusercontent.com/aaronbassett/Pass-phrase

## Setting up First Boot setup

Make sure you have installed the following:

- `~/edgesec-deploy-key.pem` - Private key for SSH login. Will be deleted after first boot.
- `~/.ssh/config` - Config file for SSH tunnel.
- `/usr/local/EDGESec/deploy/reset-hostname.bash` - Will setup the hostname/ssh-key on first boot.
- `/usr/local/EDGESec/deploy/adjectives.list` - Used to generate random hostname.
- `/usr/local/EDGESec/deploy/nouns.list` - Used to generate random hostname.
- `/etc/systemd/system/reset-hostname.service` - Used to generate random hostname on boot.
- `~/.config/systemd/user` - Used to create SSH tunnel.

- `machinectl` from `sudo apt install systemd-container`

Setup:

```bash
# required for machinectl
sudo apt install systemd-container -y
# create ~/edgesec-deploy-key.pem yourself!
chmod 600 ~/edgesec-deploy-key.pem
# warning, will overwrite old ssh config
mkdir -p ~/.ssh && cp ../ssh/nqm-ssh-tunnel/config ~/.ssh/config
sudo mkdir -p /usr/local/EDGESec/deploy && sudo cp ./reset-hostname.bash ./adjectives.list ./nouns.list /usr/local/EDGESec/deploy
sudo cp ./reset-hostname.service /etc/systemd/system
mkdir -p ~/.config/systemd/user && cp ./ssh-tunnel-key-update.service ~/.config/systemd/user

# make sure installer script exists and is in right place
chmod +x ~/EDGESec/deployment/ssh/nqm-ssh-tunnel/install.bash

sudo loginctl enable-linger # allow user systemd
systemctl --user daemon-reload
sudo systemctl daemon-reload
touch ~/.resetHostname
# run now for testing purposes only
sudo systemctl start reset-hostname.service && sudo systemctl enable reset-hostname.service
```