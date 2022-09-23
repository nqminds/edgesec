#!/usr/bin/env bash
# Time-stamp: <2014-07-31 13:31:43 (ryanc)>
#
# Description: Mirror traffic between two interfaces using Linux's
#              traffic control subsystem (tc)

trap cleanup EXIT

CLEANUP=1
SRC_IFACE=$1
DST_IFACE=$2

function cleanup() {
    if [ $CLEANUP -eq 1 ]; then
        tc qdisc del dev $SRC_IFACE ingress
        tc qdisc del dev $SRC_IFACE root
    fi
    echo
}

if [ $# -lt 2 ]; then
    echo "Usage: ${0/*\//} <src interface> <dst interface>"
    CLEANUP=0
    exit 1
fi

echo
echo "Mirroring traffic from $SRC_IFACE to $DST_IFACE"

# ingress
tc qdisc add dev $SRC_IFACE ingress
tc filter add dev $SRC_IFACE parent ffff: \
          protocol all \
          u32 match u8 0 0 \
          action mirred egress mirror dev $DST_IFACE

# egress
tc qdisc add dev $SRC_IFACE handle 1: root prio
tc filter add dev $SRC_IFACE parent 1: \
          protocol all \
          u32 match u8 0 0 \
          action mirred egress mirror dev $DST_IFACE

echo "Hit Ctrl-C or kill this session to end port mirroring"
sleep infinity

trap - EXIT
cleanup
exit 0

# End of file
