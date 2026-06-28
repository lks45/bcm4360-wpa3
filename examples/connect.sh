#!/bin/bash
# Connect the BCM4360 to a WPA3-SAE network. Usage: sudo ./connect.sh [wlan0] [conf]
set -e
IF="${1:-wlan0}"
CONF="${2:-$(dirname "$0")/wpa3-sae.conf.example}"
KO="$(dirname "$0")/../wl-src/wl.ko"

pkill -9 -f "wpa_supplicant.*$IF" 2>/dev/null || true
rmmod wl 2>/dev/null || true
insmod "$KO"
nmcli dev set "$IF" managed no 2>/dev/null || true   # keep NetworkManager off it
ip link set "$IF" up
wpa_supplicant -B -i "$IF" -D nl80211 -c "$CONF"
sleep 4
dhclient -1 "$IF" || udhcpc -i "$IF" -n -q || true
ip -4 addr show "$IF"
echo "connected on $IF"
