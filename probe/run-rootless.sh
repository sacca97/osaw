#!/usr/bin/env bash
# Same as run.sh but without sudo; requires ./setup-rootless.sh once.
set -u
cd -- "$(dirname -- "$0")" || exit 1
caps=.venv/bin-caps
for tool in python hciconfig; do
  getcap "$caps/$tool" 2>/dev/null | grep -q cap_net_admin || { echo "Run ./setup-rootless.sh first" >&2; exit 1; }
done

controller=0
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    -h|--help) exec "$caps/python" watch_poc.py --help ;;
    --transport) ((i+=1)); [[ "${args[i]:-}" =~ ^hci-socket:([0-9]+)$ ]] && controller="${BASH_REMATCH[1]}" || { echo 'Expected --transport hci-socket:<index>' >&2; exit 2; } ;;
    --transport=*) [[ "${args[i]#*=}" =~ ^hci-socket:([0-9]+)$ ]] && controller="${BASH_REMATCH[1]}" || { echo 'Expected --transport hci-socket:<index>' >&2; exit 2; } ;;
    --connection-interval-ms) ((i+=1)) ;;
  esac
done

"$caps/hciconfig" "hci$controller" down || exit $?
# Skip bytecode writes into the repo.
PYTHONDONTWRITEBYTECODE=1 exec "$caps/python" watch_poc.py "$@"
