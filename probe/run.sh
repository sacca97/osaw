#!/usr/bin/env bash
set -u
cd -- "$(dirname -- "$0")" || exit 1

# Validate options before taking the controller away from BlueZ.
controller=0
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    -h|--help) exec .venv/bin/python watch_poc.py --help ;;
    --resume) ;;
    --transport)
      ((i+=1))
      transport="${args[i]:-}"
      [[ "$transport" =~ ^hci-socket:([0-9]+)$ ]] || { echo 'Expected --transport hci-socket:<index>' >&2; exit 2; }
      controller="${BASH_REMATCH[1]}"
      ;;
    --transport=*)
      transport="${args[i]#*=}"
      [[ "$transport" =~ ^hci-socket:([0-9]+)$ ]] || { echo 'Expected --transport hci-socket:<index>' >&2; exit 2; }
      controller="${BASH_REMATCH[1]}"
      ;;
    --connection-interval-ms)
      ((i+=1))
      case "${args[i]:-}" in 7.5|15|15.0|30|30.0) ;; *) echo 'Interval must be 7.5, 15 or 30 ms' >&2; exit 2 ;; esac
      ;;
    --connection-interval-ms=*)
      case "${args[i]#*=}" in 7.5|15|15.0|30|30.0) ;; *) echo 'Interval must be 7.5, 15 or 30 ms' >&2; exit 2 ;; esac
      ;;
    *) echo "Unknown option: ${args[i]} (see --help)" >&2; exit 2 ;;
  esac
done

sudo hciconfig "hci$controller" down || exit $?
# watch_poc owns the interactive TUI; protocol/library logs remain in runs/.
sudo --preserve-env=OSAW_VERBOSE,OSAW_IDS_INLINE_TOPIC,OSAW_INFO_REPLY_PEER,OSAW_IDS_SEQ_START,OSAW_IDS_SEND_PRIORITY .venv/bin/python watch_poc.py "$@"
status=$?
[ -d runs ] && sudo chown -R "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" runs
exit "$status"
