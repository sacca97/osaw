# osaw — Open Source Apple Watch (WIP)

An experimental Python companion that pairs with an Apple Watch in setup mode
and activates it without an iPhone or an Apple account.

**Status:** supports Apple Watch SE 3 with watchOS **26.4 and 27**. Direct pairing,
activation, default app downloads, software-update discovery and terms acceptance
were demonstrated on 26.4. After upgrading to 27, saved-bond reconnect, encrypted
companion channels and Health data reception have also been demonstrated.
The companion displays received Health samples and workout summaries locally
and exposes Watch settings through a terminal dashboard. Full Health sync remains
incomplete; other models and watchOS versions may not work.

**Read [LEGAL.md](LEGAL.md) before using or contributing.** This project is not
affiliated with Apple, does not bypass Activation Lock, and is for devices you own.

## What it does

1. Finds a Watch in setup mode over BLE and pairs with the PIN it displays.
2. Bonds and brings up the encrypted link, then a Linux TUN for IP traffic.
3. Runs the IDS session and answers device-info, time-sync and account requests
   without an Apple Account.
4. Relays the Watch's activation request to Apple and starts the initial sync.
5. Announces the default Watch app list for partial app sync.
6. Advertises a Shoes proxy by default and forwards the Watch's Internet flows
   through the host, preserving the Watch's TLS traffic.
7. Keeps a terminal dashboard for connection status, stored Health data, settings
   and software-update terms. Full Health synchronization is incomplete.

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
./run.sh --resume  # reconnect using the latest saved bond
./run.sh --transport hci-socket:1 --connection-interval-ms 15
```

The relay starts and is advertised by default. Setup waits indefinitely, and
the companion stays open until you quit. Options are `--resume`, `--transport`
and `--connection-interval-ms` (plus help); transport exchanges keep their
30-second timeout.

Pairing identities and logs are stored automatically under `probe/runs/` in
separate timestamped directories. When saved bonds exist, Enter reconnects the
latest; choose 0 to pair a reset Watch without deleting older bonds.
An interrupted attempt without a completed bond needs fresh manual pairing.
Interactive runs open the TUI; protocol, library and console logs stay in the
background under the timestamped run directory. Noninteractive runs print
connection milestones; `OSAW_VERBOSE=1` enables detailed text output there.
Private file logging is always enabled.

### Dashboard

- **1 Overview:** connection status, latest stored heart rate and sync status.
- **2 Settings:** wrist, orientation and 24-hour time, each with **Off / On**
  buttons. Click a button, or select a row with Up/Down, choose with Left/Right
  and press Enter. Opening the dashboard never changes a setting.
- **3 Activity:** recent events (last 1000). `F` cycles filters (All, Errors, Health, IDS, Link), `D` shows event fields, `G` jumps back to live.
- **4 Workouts:** locally stored workout summaries. This is not a live heart-rate
  stream or a complete Health database import.
- **5 Update:** terms appear automatically when received. Scroll to read them;
  `A` explicitly accepts, and the preview closes after Watch confirmation.
  `B` dismisses the preview; `R` reads update state and `V` views available terms.
- **6 Debug:** run directory, control socket state, HCI and ERTM counters, Health state and the most frequent events.

Health read requests normally run every 20 seconds when idle; an active transfer
can continue for up to 120 seconds without progress before the next read is
scheduled. The Watch controls when data is delivered. Settings delivery and
Watch-reported effects are shown separately.
Health samples, workout summaries, raw inbox messages and sync progress are local
to the current session and are cleared on disconnect. Reconnecting starts a fresh
Health read, retaining only protocol identity UUIDs so the Watch still recognizes
the same peer. Startup also clears leftovers after an unclean process exit.

A dropped connection leaves the dashboard **DISCONNECTED**, with Watch commands
disabled and session Health data cleared. It does not reconnect or replay writes
automatically. Press `q`, then `./run.sh --resume` to reconnect. `q` or Ctrl-C
exits the companion; a noninteractive disconnected run waits for Ctrl-C.


## Layout

- `probe/` — the companion and its tests (`watch_poc.py` is the entry point).
- `docs/` — protocol sequence charts.
- `LEGAL.md`, `LICENSE` — legal notice and MIT licence.

## Licence

MIT — see [LICENSE](LICENSE). Dependencies keep their own licences.
