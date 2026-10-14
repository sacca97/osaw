#!/usr/bin/env bash
# One-time: give private copies of python and hciconfig the network
# capabilities the companion needs, so run-rootless.sh needs no sudo at run time.
# The companion configures its TUN over netlink itself (iproute2 drops file
# capabilities, so a capped `ip` would not work). Only these copies (inside .venv/bin-caps, owned by you) get capabilities;
# the system python3, ip and hciconfig are left untouched.
set -eu
cd -- "$(dirname -- "$0")"
[ -x .venv/bin/python ] || { echo '.venv missing' >&2; exit 1; }
dir=.venv/bin-caps
mkdir -p "$dir"
cp --remove-destination "$(readlink -f .venv/bin/python)" "$dir/python"
cp --remove-destination "$(command -v hciconfig)" "$dir/hciconfig"
sudo setcap cap_net_raw,cap_net_admin+eip "$dir/python"
sudo setcap cap_net_admin+eip "$dir/hciconfig"
getcap "$dir"/*
echo 'Re-run this after a Python upgrade (the copy does not follow system updates).'
