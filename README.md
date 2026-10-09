# osaw — a Linux companion for Apple Watch (research PoC) (WIP)

An experimental Python companion that pairs with an Apple Watch in setup mode
and activates it without an iPhone. It runs the initial sync to prepare the
Watch for standalone use. This project is a research proof of concept for
interoperability.

**Status:** demonstrated on one Apple Watch SE 3 (watchOS 26.4), from reset to a
Watch that is usable on its own. App sync works in part; full support is not
confirmed. Software updates and Apple Account sign-in are not implemented.
Other companion services remain incomplete. Other models and watchOS versions
may not work.

**Read [LEGAL.md](LEGAL.md) before using or contributing.** This project is not
affiliated with Apple, does not bypass Activation Lock, and is for devices you own.

## What it does

1. Finds a Watch in setup mode over BLE and pairs with the PIN it displays.
2. Bonds and brings up the encrypted link, then a Linux TUN for IP traffic.
3. Runs the IDS session and answers device-info, time-sync and account requests
   without an Apple Account.
4. Relays the Watch's activation request to Apple and starts the initial sync.
5. Announces the default Watch app list for partial app sync.

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
The launcher disables `hci0` and takes it from BlueZ.

```sh
cd probe
./run.sh                 # fresh pairing, asks for the Watch PIN
./run.sh --resume        # reconnect to the most recent saved pairing
```

State and logs go to `probe/runs/` and can contain private keys and device data.
Never commit or share these files. Set `STATE` to select a different pairing
directory. `./run.sh --help` lists the options. `--hold 0` keeps the connection
until you stop it.

## Layout

- `probe/` — the companion and its tests (`watch_poc.py` is the entry point).
- `docs/` — protocol sequence charts.
- `LEGAL.md`, `LICENSE` — legal notice and MIT licence.

## Licence

MIT — see [LICENSE](LICENSE). Dependencies keep their own licences.
