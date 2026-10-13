# osaw — Open Source Apple Watch (WIP)

An experimental Python companion that pairs with an Apple Watch in setup mode
and activates it without an iPhone or an Apple account.

**Status:** works on  Apple Watch SE 3 (watchOS 26.4), watch is usable on its own with all the default application working after the initial sync. Software updates are not working. Other models and watchOS versions may not work.

**Read [LEGAL.md](LEGAL.md) before using or contributing.** This project is not
affiliated with Apple, does not bypass Activation Lock, and is for devices you own.

## What it does

1. Finds a Watch in setup mode over BLE and pairs with the PIN it displays.
2. Bonds and brings up the encrypted link, then a Linux TUN for IP traffic.
3. Runs the IDS session and answers device-info, time-sync and account requests
   without an Apple Account.
4. Relays the Watch's activation request to Apple and starts the initial sync.
5. Announces the default Watch app list for partial app sync.
6. Optionally advertises a Shoes proxy and forwards the Watch's Internet flows
   through the host, preserving the Watch's TLS traffic.

The message flow is in [docs/protocol-overview.md](docs/protocol-overview.md).

## Requirements

Use Linux with Python 3.11+, a BLE controller, `/dev/net/tun` and `iproute2`.
The companion needs exclusive access to the controller and root or
`CAP_NET_RAW`/`CAP_NET_ADMIN`. The launcher also needs `sudo` and `hciconfig`.
Activation needs Internet access.

```sh
python3 -m venv probe/.venv
probe/.venv/bin/python -m pip install -r probe/requirements.txt
```

## Offline checks (no Watch, no Apple contact)

```sh
cd probe
(
  for test_file in tests/test_*.py; do
    .venv/bin/python "$test_file" || exit "$?"
  done
)
```

This runs all test scripts and stops with an error if a check fails.
The intermediate-exchange check needs `tshark`. The SA_INIT check skips its
optional steps when `tshark` or the private reference capture is absent.
No private capture is required.

## Running against your own Watch

Charge the Watch. Open its pairing screen.
Use a Bluetooth adapter that does not connect your keyboard or mouse.
The launcher releases the selected HCI controller from BlueZ (default `hci0`).

```sh
cd probe
./run.sh
./run.sh --transport hci-socket:1 --connection-interval-ms 15
```

The relay starts and is advertised by default. Setup waits indefinitely, and
the companion stays connected until Ctrl-C. The only options are `--transport`
and `--connection-interval-ms` (plus help); transport exchanges keep their
30-second timeout.

Pairing identities and logs are stored automatically under `probe/runs/` in
separate timestamped directories. When saved bonds exist, Enter reconnects the
latest; choose 0 to pair a reset Watch without deleting older bonds.
An interrupted attempt without a completed bond needs fresh manual pairing.
Connection milestones and failures appear by default. `OSAW_VERBOSE=1 ./run.sh`
shows detailed terminal events; private file logging is always enabled.


## Layout

- `probe/` — the companion and its tests (`watch_poc.py` is the entry point).
- `docs/` — protocol sequence charts.
- `LEGAL.md`, `LICENSE` — legal notice and MIT licence.

## Licence

MIT — see [LICENSE](LICENSE). Dependencies keep their own licences.
