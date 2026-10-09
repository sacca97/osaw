#!/usr/bin/env bash
# Pair a Watch in setup mode, or reconnect with: ./run.sh --resume
# Needs raw HCI access (root or CAP_NET_RAW/CAP_NET_ADMIN). Extra arguments go to watch_poc.py.

# Help needs neither root nor the Bluetooth adapter.
for arg in "$@"; do
  case "$arg" in -h|--help) exec .venv/bin/python watch_poc.py --help ;; esac
done

# State directory: STATE=... wins. With --resume the most recently saved pairing in runs/ is reused;
# otherwise a new timestamped one is created.
resume=0
for arg in "$@"; do [ "$arg" = "--resume" ] && resume=1; done
if [ -z "${STATE:-}" ]; then
  if [ "$resume" = 1 ]; then
    latest=$(ls -t runs/pairing-*/pairing.json 2>/dev/null | head -1)
    [ -n "$latest" ] || { echo "no saved pairing under runs/ to resume" >&2; exit 1; }
    STATE=$(dirname "$latest")
  else
    STATE="runs/pairing-$(date +%Y%m%d-%H%M%S)"
  fi
fi
echo "state: $STATE"

sudo hciconfig hci0 down

sudo .venv/bin/python watch_poc.py --transport hci-socket:0 --state "$STATE" --setup-timeout 0 --hold 0 "$@"
status=$?

[ -d runs ] && sudo chown -R "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" runs

exit $status
