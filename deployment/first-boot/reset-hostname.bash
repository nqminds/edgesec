#!/usr/bin/env bash
# changes the hostname of the apu if the file ~/.resetHostname exists
# disables the reset-hostname.service service if it can
# deletes the file after the hostname is changed

set -o errexit

command_name="${0}"

print_help() {
	echo "Usage: bash ${command_name} [OPTION]... [HOSTNAME]"
	echo "Changes the hostname to a pseudo-random one, changing with wifi ap"
	echo "and SSH key appropriately."
	echo ""
	echo "-h/--help           Display this help and exit."
	echo ""
	echo "ARGS:"
	echo "  HOSTNAME"
	echo "    If given, set the hostname of the device to this."
	echo "    Else, pick a random hostname in form edgesec-[adjective]-[noun]"
}

while test $# -gt 0; do
    case "$1" in
        -h|--help)
                print_help
                exit 0
                ;;
        *)
                break
                ;;
    esac
done

if [ "$#" -gt 1 ]; then
	(>&2 echo "Error: Was only expecting max 1 Arg, got $#: $*")
	(>&2 print_help)
	exit 1
fi

USR='ubuntu'
USR_HOME_DIR="/home/${USR}"
EDGE_SEC_DIR="${USR_HOME_DIR}/EDGESEC"
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

if [ ! -f "${USR_HOME_DIR}/.resetHostname" ]; then
	# only run this script if ~/.resetHostname exists
	exit 0
fi

function randomHostname() {
	ADJECTIVE_LIST="${THIS_DIR}/adjectives.list"
	LINES=$(wc -l < "$ADJECTIVE_LIST") # line count
	RANDOM_LINE=$(( $RANDOM % $LINES )) # get a random val between 0 and $LINES
	# sed hax https://stackoverflow.com/a/6022431/10149169
	ADJECTIVE=$(sed "${RANDOM_LINE}q;d" "$ADJECTIVE_LIST") # picks a line

	NOUN_LIST="${THIS_DIR}/nouns.list"
	LINES=$(wc -l < "$NOUN_LIST") # line count
	RANDOM_LINE=$(( $RANDOM % $LINES )) # get a random val between 0 and $LINES
	# sed hax https://stackoverflow.com/a/6022431/10149169
	NOUN=$(sed "${RANDOM_LINE}q;d" "$NOUN_LIST") # picks a line
	HOSTNAME="edgesec-${ADJECTIVE}-${NOUN}"
	echo "${HOSTNAME:0:63}" # truncate to 63 chars
}

# copy a new ssh key to the server
function setupSSHTunnel() {
	machinectl shell "$USR"@ /usr/bin/systemctl --user start ssh-tunnel-key-update.service
	machinectl shell "$USR"@ /usr/bin/systemctl --user enable ssh-tunnel-key-update.service
}

HOSTNAME="$1"
if [ -z "$1" ]; then
	HOSTNAME="$(randomHostname)"
fi

orig_hostname="$(hostname)"
sudo hostnamectl set-hostname "$HOSTNAME"

setupSSHTunnel

rm "${USR_HOME_DIR}/.resetHostname"
sudo systemctl disable reset-hostname.service || true
