#!/usr/bin/env python3
"""Read-only terminal monitor for a PoC run; no Bluetooth or process access."""
import argparse
from collections import Counter, deque
from datetime import datetime
import json
from pathlib import Path
import struct
import sys
import time


class Monitor:
    def __init__(self, directory):
        self.directory = directory
        self.event_offset, self.capture_offset = 0, 16
        self.recent = deque(maxlen=12)
        self.counts = Counter()
        self.milestones = []
        self.last_protocol = self.heartbeat = self.started = None
        self.event_count, self.bad_events = 0, 0

    def refresh(self):
        with (self.directory / 'events.jsonl').open() as events:
            events.seek(self.event_offset)
            while line := events.readline():
                if not line.endswith('\n'):
                    break  # Writer hasn't finished this record yet.
                self.event_offset = events.tell()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self.bad_events += 1
                    continue
                self.event_count += 1
                name = event.get('event', '?')
                if name == 'start':
                    self.started = event
                if name == 'progress':
                    self.heartbeat = event
                    continue
                self.last_protocol = event
                self.recent.append(event)
                if name in ('pin_authenticated', 'bluetooth_bond_confirmed',
                            'normal_ike_authenticated', 'normal_link_ready',
                            'ids_hello_received', 'ids_lanes_ready', 'ids_device_info_verified',
                            'watch_activation_confirmed', 'setup_protocol_complete',
                            'reconnected_to_initialized_watch',
                            'proxy_announcement_acknowledged', 'relay_proxy_connected'):
                    label = name.replace('_', ' ') + (' ' + event['lane'] if 'lane' in event else '')
                    if label not in self.milestones:
                        self.milestones.append(label)
        capture = self.directory / 'hci.btsnoop'
        stat = capture.stat()
        with capture.open('rb') as data:
            if stat.st_size >= 16 and data.read(8) != b'btsnoop\0':
                raise ValueError('Capture is not BTSnoop')
            data.seek(self.capture_offset)
            while stat.st_size - self.capture_offset >= 24:
                _, included, flags, _, _ = struct.unpack('>IIIIQ', data.read(24))
                if included < 1 or included > 65536:
                    raise ValueError('Invalid BTSnoop packet length')
                if self.capture_offset + 24 + included > stat.st_size:
                    break
                kind = data.read(1)[0]
                label = 'ACL RX' if flags & 1 else 'ACL TX'
                self.counts[label if kind == 2 else {1: 'commands', 4: 'events'}.get(kind, 'other')] += 1
                self.capture_offset += 24 + included
                data.seek(self.capture_offset)
        return stat

    def display(self, stat, previous, elapsed):
        now = time.time()
        lines = [f'Apple Watch run monitor  {datetime.now():%H:%M:%S}', str(self.directory.resolve())]
        if self.started:
            lines.append(f"Run age: {max(0, now - self.started['epoch']):.0f}s | resume: {self.started.get('resume', False)}")
        if self.last_protocol:
            event = self.last_protocol
            lines.append(f"Last protocol event: {event['event']} ({max(0, now - event['epoch']):.0f}s ago)")
        if self.heartbeat:
            event = self.heartbeat
            lines.append(f"Heartbeat: {max(0, now - event['epoch']):.0f}s ago | stage: {event.get('stage', '?')} | "
                         f"IDS: {event.get('ids_phase', '?')} | lanes: {event.get('ids_lanes', 0)} | pending ERTM: {event.get('ertm_pending', 0)}")
            if 'ertm_tx_frames' in event:
                lines.append(f"ERTM frames: sent {event['ertm_tx_frames']} | acknowledged {event.get('ertm_acked', 0)} | "
                             f"retransmitted {event.get('ertm_retransmissions', 0)}")
            if 'watch_is_setup' in event:
                lines.append('Setup: ' + ' | '.join(f'{key}={event.get(key)}' for key in
                             ('activation', 'watch_setup_present', 'watch_is_setup',
                              'watch_sync_progress', 'watch_global_progress', 'client_sync_progress',
                              'sync_complete', 'completion_ack')))
        else:
            lines.append('Heartbeat: not emitted by this run (available after restarting updated code)')
        lines.append(f'Visible capture: {stat.st_size:,} bytes | last disk write {max(0, now - stat.st_mtime):.0f}s ago')
        lines.append('HCI totals: ' + ' | '.join(f'{key}: {self.counts[key]}' for key in ('ACL RX', 'ACL TX', 'commands', 'events')))
        if previous is not None:
            lines.append(f"Last {elapsed:.1f}s: RX +{self.counts['ACL RX'] - previous['ACL RX']} | TX +{self.counts['ACL TX'] - previous['ACL TX']}")
        lines.extend(['', 'Observed milestones:'] + ['  ' + item for item in self.milestones])
        lines.extend(['', f'Recent events ({self.event_count} total):'])
        for event in self.recent:
            stamp = datetime.fromtimestamp(event['epoch']).strftime('%H:%M:%S')
            # Do not display PINs, keys, device identifiers or packet bodies.
            fields = ' '.join(f'{key}={event[key]}' for key in
                              ('lane', 'port', 'type', 'length', 'command', 'flags', 'operation', 'received', 'total', 'attempt', 'error',
                               'mode', 'response', 'correlated', 'success_present', 'accepted',
                               'property_count', 'state_name', 'timestamp', 'applied', 'state',
                               'watch_setup_present', 'watch_is_setup', 'activation', 'sync_complete',
                               'completion_ack', 'watch_sync_progress', 'watch_global_progress', 'client_sync_progress',
                               'payload_format', 'numeric_fields', 'bundle_id', 'error_domain',
                               'archived_errors', 'application_handler', 'response_expected',
                               'error_details', 'error_field_details', 'collection_counts', 'notify', 'message_id',
                               'endpoint', 'address', 'proxy_flags', 'ike_ack', 'host', 'service',
                               'bytes_to_upstream', 'bytes_to_watch', 'errno', 'phase', 'proxy_probe',
                               'destination', 'source_port', 'direction', 'prefix_format',
                               'bytes_from_watch', 'bytes_from_upstream', 'protocol', 'count',
                               'message_type', 'host_unix', 'host_monotonic', 'timezone',
                               'remote_mach', 'remote_rtc', 'uncertainty', 'time_source',
                               'tcp_pending', 'waited_seconds', 'queued_packets',
                               'ertm_window', 'ertm_mps', 'ertm_tx_frames', 'ertm_acked', 'ertm_retransmissions',
                               'interval_ms', 'requested_interval_ms', 'latency', 'supervision_timeout_ms')
                              if key in event)
            lines.append(f"  {stamp} {event['event']} {fields}")
        if self.bad_events:
            lines.append(f'Ignored malformed event records: {self.bad_events}')
        lines.extend(['', 'Traffic/heartbeats show activity; only milestones show protocol progress.',
                      'Older runs buffer captures: quiet disk counters do not prove a stalled link.',
                      'Ctrl-C closes this monitor only.'])
        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, help='Pin a specific run directory; default selects the latest once')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent / 'runs')
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--once', action='store_true', help='Print one snapshot and exit')
    parser.add_argument('--plain', action='store_true', help='Print snapshots without terminal clearing')
    args = parser.parse_args()
    if not 0 < args.interval < float('inf'):
        parser.error('--interval must be finite and positive')
    try:
        directory = args.run
        if directory is None:
            candidates = sorted(path for path in args.output.iterdir()
                                if path.name[:8].isdigit() and (path / 'events.jsonl').is_file())
            if not candidates:
                raise ValueError('No run with events.jsonl found')
            directory = candidates[-1]
        monitor = Monitor(directory)
        previous, previous_time = None, time.monotonic()
        while True:
            stat = monitor.refresh()
            now = time.monotonic()
            if sys.stdout.isatty() and not args.plain:
                print('\033[2J\033[H', end='')
            print(monitor.display(stat, previous, now - previous_time), flush=True)
            if args.once:
                return
            previous, previous_time = monitor.counts.copy(), now
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return
    except (OSError, ValueError) as error:
        parser.exit(1, f'Monitor: {error}\nIf this run is root-owned, launch the monitor with sudo.\n')


if __name__ == '__main__':
    main()
