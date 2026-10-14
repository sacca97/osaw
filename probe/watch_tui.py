#!/usr/bin/env python3
"""Monitor a companion in a second terminal; optional settings use its local socket."""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import curses
from datetime import datetime
import json
from pathlib import Path
import socket
import time
import textwrap
from functools import lru_cache

from monitor_run import Monitor
from operational import SETTINGS


def request(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(135 if command.get('command') == 'update_accept_terms' else 40)
        client.connect(str(path))
        client.sendall(json.dumps(command).encode() + b'\n')
        data = bytearray()
        while b'\n' not in data and len(data) < 2 * 1024 * 1024:
            part = client.recv(min(65536, 2 * 1024 * 1024 - len(data)))
            if not part:
                break
            data.extend(part)
        if not data.endswith(b'\n'):
            raise ValueError('Incomplete control response')
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError('Invalid control response')
        return result


def on_off(value):
    return 'On' if value is True else 'Off' if value is False else 'Not reported'


def palette(screen):
    colors = {'text': curses.A_NORMAL, 'muted': curses.A_DIM,
              'accent': curses.A_BOLD, 'good': curses.A_BOLD,
              'warn': curses.A_BOLD, 'bad': curses.A_BOLD,
              'selected': curses.A_REVERSE, 'border': curses.A_DIM}
    if curses.has_colors():
        try:
            curses.start_color()
            wide = curses.COLORS >= 256
            bg = 234 if wide else curses.COLOR_BLACK
            shades = (252, 245, 81, 84, 221, 203, 117, 239) if wide else (7, 7, 6, 2, 3, 1, 7, 4)
            for index, (name, foreground) in enumerate(zip(colors, shades), 1):
                curses.init_pair(index, foreground, 24 if wide and name == 'selected' else
                                 curses.COLOR_BLUE if name == 'selected' else bg)
                colors[name] = curses.color_pair(index)
            screen.bkgd(' ', colors['text'])
        except curses.error:
            pass
    return colors


def put(screen, y, x, text, style=0, width=None):
    height, columns = screen.getmaxyx()
    if not 0 <= y < height or not 0 <= x < columns - 1:
        return
    available = columns - x - 1
    text = ''.join(ch if ch.isprintable() else ' ' for ch in str(text))
    try:
        screen.addnstr(y, x, text, max(0, min(available, available if width is None else width)), style)
    except curses.error:
        pass


def panel(screen, y, x, height, width, title, colors):
    try:
        screen.attron(colors['border'])
        screen.hline(y, x + 1, curses.ACS_HLINE, width - 2)
        screen.hline(y + height - 1, x + 1, curses.ACS_HLINE, width - 2)
        screen.vline(y + 1, x, curses.ACS_VLINE, height - 2)
        screen.vline(y + 1, x + width - 1, curses.ACS_VLINE, height - 2)
        for row, col, corner in ((y, x, curses.ACS_ULCORNER), (y, x + width - 1, curses.ACS_URCORNER),
                                  (y + height - 1, x, curses.ACS_LLCORNER),
                                  (y + height - 1, x + width - 1, curses.ACS_LRCORNER)):
            screen.addch(row, col, corner)
    except curses.error:
        pass
    finally:
        screen.attroff(colors['border'])
    put(screen, y, x + 2, ' ' + title + ' ', colors['accent'] | curses.A_BOLD, width - 4)


def age_label(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f'{seconds}s ago'
    if seconds < 3600:
        return f'{seconds // 60}m {seconds % 60:02d}s ago'
    if seconds < 86400:
        return f'{seconds // 3600}h {(seconds % 3600) // 60:02d}m ago'
    return f'{seconds // 86400}d ago'


def local_date(timestamp, pattern):
    try:
        return datetime.fromtimestamp(timestamp).strftime(pattern)
    except (ValueError, OverflowError, OSError):
        return 'Invalid date'


def duration_label(seconds):
    if seconds is None:
        return '-'
    seconds = int(seconds)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f'{hours}h {minutes:02d}m' if hours else f'{minutes}m {seconds:02d}s'


HEALTH_LABELS = {
    'prepared': 'Preparing Health', 'restore_sent': 'Waiting for Restore acceptance',
    'restore_remote_finished': 'Restore accepted', 'changes_sent': 'Requesting Health data',
    'watch_stream_waiting': 'Waiting for the Watch', 'receiving': 'Receiving Health data',
    'finished': 'Last transfer finished', 'watch_export_failed': 'Watch export error',
    'changes_unknown': 'Read unconfirmed; scheduled to resume', 'poll_wait': 'Waiting for next read',
    'changes_rejected': 'Watch rejected the read', 'restore_rejected': 'Watch rejected Restore',
    'restore_unknown': 'Restore needs investigation',
}



@lru_cache(maxsize=2)
def wrap_terms(text, width):
    return [line for paragraph in text.splitlines() for line in (textwrap.wrap(paragraph, width) or [''])]


TABS = ('Overview', 'Settings', 'Activity', 'Workouts', 'Update', 'Debug')
SETTINGS_TOP = {0: 12, 1: 4}
ACTIVITY_FILTERS = (('All', ''), ('Errors', 'error'), ('Health', 'health'), ('IDS', 'ids_'),
                    ('Link', 'ike|normal|ertm|nr_|relay|nwsc'))


def event_matches(event, flt):
    if not flt:
        return True
    name = event.get('event', '')
    if flt == 'error':
        return bool(event.get('error')) or 'fail' in name or 'reject' in name or 'lost' in name
    return any(part in name for part in flt.split('|'))


def event_detail(event):
    skip = {'event', 'epoch'}
    return '  '.join(f'{k}={v}' for k, v in event.items() if k not in skip and not isinstance(v, (dict, list)))


def uptime_label(monitor):
    start = (monitor.started or {}).get('epoch')
    return duration_label(time.time() - start) if start else '-'


def rule(screen, y, x, width, colors):
    try:
        screen.attron(colors['border'])
        screen.hline(y, x, curses.ACS_HLINE, max(0, width))
    except curses.error:
        pass
    finally:
        screen.attroff(colors['border'])


def kv(screen, y, x, width, label, value, colors, tone='text', label_width=22):
    put(screen, y, x, label, colors['muted'], label_width)
    put(screen, y, x + label_width, value, colors[tone], max(0, width - label_width))


def render(screen, monitor, status, fresh, ready, selected, draft, notice, tab, scroll, integrated, colors,
           update_terms=None, ui=None):
    ui = ui or {}
    screen.erase()
    h, w = screen.getmaxyx()
    c = colors
    bold = curses.A_BOLD
    if h < 22 or w < 72:
        put(screen, 1, 2, 'OSAW  /  Apple Watch companion', c['accent'] | bold)
        put(screen, 3, 2, 'Resize this terminal to at least 72 columns x 22 rows.', c['warn'])
        put(screen, 5, 2, 'Logging and the companion continue in the background.', c['muted'])
        put(screen, 7, 2, 'q  Stop companion' if integrated else 'q  Close monitor', c['text'])
        screen.refresh()
        return
    hb = monitor.heartbeat or {}
    last = monitor.last_protocol or monitor.started or {}
    last_epoch = max(last.get('epoch', 0), hb.get('epoch', 0))
    link_fresh = last_epoch and time.time() - last_epoch < 30
    connected = not monitor.stopped and not monitor.disconnected and (ready or link_fresh and hb.get('ids_phase') == 'ready')
    badge, badge_color = ('STOPPED', 'bad') if monitor.stopped else (
        ('DISCONNECTED', 'warn') if monitor.disconnected else ('CONNECTED', 'good') if connected else ('CONNECTING', 'warn') if link_fresh else ('NO RECENT STATUS', 'warn'))
    lanes = 0 if monitor.disconnected else status.get('ids_lanes', hb.get('ids_lanes', 0))

    # Header: identity and link state, then the tab strip.
    put(screen, 0, 2, 'OSAW', c['accent'] | bold)
    put(screen, 0, 8, 'Apple Watch companion', c['text'] | bold)
    put(screen, 0, w - len(badge) - 12, datetime.now().strftime('%H:%M:%S'), c['muted'])
    put(screen, 0, w - len(badge) - 3, '● ' + badge, c[badge_color] | bold)
    put(screen, 1, 2, f'{monitor.directory.name}   up {uptime_label(monitor)}   {lanes}/2 channels   '
        f'relay {monitor.event_counts["relay_proxy_connected"]}'
        + (('   last event ' + (age_label(time.time() - last_epoch) if last_epoch else 'none')) if w >= 100 else ''),
        c['muted'], w - 4)
    x = 2
    for index, title in enumerate(TABS):
        label = f' {index + 1} {title} '
        put(screen, 2, x, label, c['selected'] | bold if tab == index else c['muted'])
        x += len(label) + 1
    rule(screen, 3, 1, w - 2, c)

    def health_card(y, x, width):
        health = status.get('health', {})
        panel(screen, y, x, 7, width, 'HEALTH', c)
        hr = health.get('latest_hr')
        if hr:
            timestamp, bpm = hr
            put(screen, y + 1, x + 2, f'{bpm:g} bpm', c['accent'] | bold)
            put(screen, y + 1, x + 14, 'last stored reading, ' + age_label(time.time() - timestamp), c['muted'], width - 16)
        else:
            put(screen, y + 1, x + 2, 'Waiting for heart-rate data', c['muted'], width - 4)
        if 'samples' in health:
            detail = f'{health["heart_rate_samples"]:,} HR readings  ·  {health["samples"]:,} total samples'
        else:
            detail = f'{monitor.health_observations:,} HR log observations (unique counts unavailable)'
        put(screen, y + 2, x + 2, detail, c['text'], width - 4)
        phase = health.get('phase') or ''
        label = HEALTH_LABELS.get(phase, 'Awaiting Health status')
        tone = ('bad' if 'failed' in phase or 'rejected' in phase else 'warn' if 'unknown' in phase
                else 'good' if phase in ('receiving', 'finished', 'restore_remote_finished') else 'muted')
        put(screen, y + 3, x + 2, label, c[tone], width - 4)
        due = health.get('next_read_at')
        next_read = (f'Next read in {max(0, int(due - time.time()))}s' if due is not None else 'Listening for Watch data')
        if phase == 'receiving':
            next_read = 'Receiving Watch data; next read follows this transfer'
        if monitor.disconnected:
            next_read = 'Disconnected; sync paused'
        elif not fresh:
            next_read = 'Monitor only / last saved status' if status else 'Waiting for companion controls'
        session = health.get('incoming_session')
        if session and session[0] == 'watch_export_failed':
            next_read += f'  ·  Watch error {session[2]}'
        put(screen, y + 4, x + 2, next_read, c['muted'], width - 4)
        caption = ('Recorded ' + local_date(hr[0], '%Y-%m-%d %H:%M:%S') + ' (stored history, not live)'
                   if hr else 'Stored history; this is not a live sensor stream.')
        put(screen, y + 5, x + 2, caption, c['muted'], width - 4)

    def link_card(y, x, width):
        panel(screen, y, x, 7, width, 'CONNECTION', c)
        rows = (('Encrypted channels', f'{lanes}/2'),
                ('Bluetooth queued', hb.get('ertm_pending', '-')),
                ('Retransmissions', hb.get('ertm_retransmissions', '-')),
                ('HCI RX / TX', f'{monitor.counts["ACL RX"]:,} / {monitor.counts["ACL TX"]:,}'),
                ('Last activity', age_label(time.time() - last_epoch) if last_epoch else 'Waiting'))
        for i, (label, value) in enumerate(rows):
            kv(screen, y + i + 1, x + 2, width - 4, label, value, c, label_width=20)

    def settings_card(y, height):
        panel(screen, y, 1, height, w - 2, 'WATCH SETTINGS', c)
        for index, name in enumerate(SETTINGS):
            row = status.get('settings', {}).get(name, {})
            active = selected == index
            put(screen, y + 2 + index, 3, '▸' if active and ready else ' ', c['accent'])
            put(screen, y + 2 + index, 5, SETTINGS[name][0],
                c['accent'] | bold if active else c['text'], w - 29)
            for value, x, label in ((False, w - 21, '[ Off ]'), (True, w - 12, '[ On ]')):
                style = c['good'] | bold if row.get('observed') is value else c['muted']
                if active and draft[name] is value:
                    style = c['selected'] | bold
                if not ready:
                    style = c['muted']
                put(screen, y + 2 + index, x, label, style)

    body = h - 7  # panel height between the tab rule and the footer rule
    if tab == 0:
        if w >= 110:
            left = (w - 5) * 3 // 5
            health_card(4, 1, left)
            link_card(4, left + 2, w - left - 3)
        else:
            health_card(4, 1, w - 2)
        settings_card(SETTINGS_TOP[0], 7 if h < 25 else 8)
    elif tab == 1:
        settings_card(SETTINGS_TOP[1], 7)
        put(screen, 12, 3, 'Left/Right choose a draft value, Enter writes it once, C clears the draft. Nothing is retried.', c['muted'], w - 6)
    elif tab == 3:
        health = status.get('health', {})
        panel(screen, 4, 1, body, w - 2, f'RECORDED WORKOUTS  ·  {health.get("workout_count", 0)} stored', c)
        rows = health.get('workouts', [])
        labels = health.get('workout_labels', [])
        if rows:
            for x, text in ((4, 'STARTED'), (25, 'ACTIVITY'), (49, 'DURATION'), (61, 'ENDED')):
                put(screen, 6, x, text, c['muted'] | bold)
            rule(screen, 7, 3, w - 6, c)
            for index, (activity, start, end, duration) in enumerate(rows):
                put(screen, 8 + index, 4, local_date(start, '%Y-%m-%d %H:%M'), c['text'], 19)
                label = labels[index] if index < len(labels) else (f'Type {activity}' if activity is not None else 'Not reported')
                put(screen, 8 + index, 25, label, c['accent'], 22)
                put(screen, 8 + index, 49, duration_label(duration), c['text'], 11)
                put(screen, 8 + index, 61, local_date(end, '%H:%M'), c['muted'], w - 65)
            if h >= 27:
                put(screen, h - 6, 4, 'Latest five stored summaries; detailed events stay private on disk.', c['muted'], w - 8)
        else:
            put(screen, 6, 4, 'No saved workout received yet.' if 'workouts' in health else
                'This running companion has no workout summary decoder.', c['text'], w - 8)
            put(screen, 8, 4, 'Save a workout on the Watch and keep the companion connected.', c['muted'], w - 8)
            put(screen, 9, 4, 'Live activities and configurations are not saved workouts.', c['muted'], w - 8)
    elif tab == 4:
        update = status.get('software_update', {})
        panel(screen, 4, 1, body, w - 2, 'SOFTWARE UPDATE', c)
        title = 'watchOS ' + str(update.get('version') or '?') + '  ·  ' + str(update.get('build') or 'No descriptor received')
        put(screen, 5, 4, title, c['accent'] | bold, w - 8)
        if update_terms:
            same = update_terms.get('token') == update.get('token')
            put(screen, 6, 4, 'TERMS  ·  Up/Down or PgUp/PgDn to read' if same else
                'Update changed: press V to view the current terms.', c['muted'] if same else c['warn'], w - 8)
            rule(screen, 7, 3, w - 6, c)
            lines = wrap_terms(update_terms.get('text', ''), max(1, w - 8))
            room = max(1, h - 14)
            start = min(scroll, max(0, len(lines) - room))
            for index, line in enumerate(lines[start:start + room]):
                put(screen, 8 + index, 4, line, c['text'], w - 8)
            if len(lines) > room:
                put(screen, 6, w - 14, f'{start + 1}-{min(len(lines), start + room)}/{len(lines)}', c['muted'])
        else:
            rows = (('State query', update.get('query_state', 'Not available in this running core')),
                    ('Terms received', 'Yes' if update.get('terms_available') else 'No'),
                    ('Watch reports accepted', on_off(update.get('watch_accepted'))),
                    ('Acceptance request', update.get('acceptance_state', 'Not requested')))
            for i, (label, value) in enumerate(rows):
                kv(screen, 7 + i, 4, w - 8, label, value, c, label_width=26)
            put(screen, 12, 4, 'R reads Watch state. V displays its terms. A accepts displayed terms.', c['muted'], w - 8)
            if h >= 25:
                put(screen, 14, 4, 'Acceptance can let the Watch continue the update you requested.', c['warn'], w - 8)
    elif tab == 5:
        panel(screen, 4, 1, body, w - 2, 'DEBUG', c)
        col = max(40, (w - 4) // 2)
        socket_path = monitor.directory / 'control.sock'
        put(screen, 5, 4, 'RUN', c['accent'] | bold)
        info = (('Directory', str(monitor.directory)),
                ('Control socket', ('present' if socket_path.exists() else 'absent') + (
                    f', status {int(time.monotonic() - ui.get("status_at", 0))}s old' if ui.get('status_at') else '')),
                ('Controls ready', on_off(bool(ready))),
                ('Events read', f'{monitor.event_count:,}  ({monitor.bad_events} unparsable)'),
                ('HCI packets', '  '.join(f'{k} {v:,}' for k, v in sorted(monitor.counts.items()))),
                ('Health messages', f'{monitor.health_messages:,}  state: {monitor.health_state}'),
                ('Phase', f'{hb.get("ids_phase", "-")}  hello={hb.get("ids_hello", "-")}  info={hb.get("peer_info", "-")}'),
                ('ERTM frames', f'tx {hb.get("ertm_tx_frames", "-")}  acked {hb.get("ertm_acked", "-")}  '
                 f'pending {hb.get("ertm_pending", "-")}  retx {hb.get("ertm_retransmissions", "-")}'))
        for i, (label, value) in enumerate(info):
            kv(screen, 6 + i, 4, w - 8, label, value, c, label_width=18)
        top = 6 + len(info) + 1
        put(screen, top, 4, 'MOST FREQUENT EVENTS', c['accent'] | bold)
        room = max(0, h - 7 - top - 1)
        counts = monitor.event_counts.most_common(room * 2)
        half = (room + 1) // 2 if w >= 110 else room
        for i, (name, count) in enumerate(counts[:room if w < 110 else room * 2]):
            column, row = divmod(i, max(1, half)) if w >= 110 else (0, i)
            put(screen, top + 1 + row, 4 + column * col, f'{count:>7,}  {name}',
                c['bad'] if name.endswith('_failed') else c['text'], col - 2)
    else:
        flt_name, flt = ACTIVITY_FILTERS[ui.get('filter', 0) % len(ACTIVITY_FILTERS)]
        detailed = ui.get('details', False)
        events = [event for event in monitor.recent if event_matches(event, flt)]
        title = f'ACTIVITY  ·  filter: {flt_name}  ·  {len(events)} shown' + ('  ·  details' if detailed else '')
        panel(screen, 4, 1, body, w - 2, title, c)
        room = max(0, body - 2)
        end = max(0, len(events) - scroll)
        visible = events[max(0, end - room):end]
        for i, event in enumerate(visible):
            name = event['event']
            color = c['bad'] if event.get('error') or name.endswith('_failed') else c['text']
            text = name.replace('_', ' ').capitalize()
            if event.get('error'):
                text += '  /  ' + str(event['error'])
            elif detailed:
                text = f'{name}  {event_detail(event)}'
            put(screen, 5 + i, 4, datetime.fromtimestamp(event['epoch']).strftime('%H:%M:%S'), c['muted'], 9)
            put(screen, 5 + i, 14, text, color, w - 18)
        if not visible:
            put(screen, 5, 4, 'No matching events yet.', c['muted'])
        elif scroll:
            put(screen, 4, w - 20, f' {scroll} newer hidden ', c['warn'])

    # Footer: status notice, rule, context keys.
    if monitor.disconnected and not monitor.stopped:
        notice = 'Watch disconnected. History remains available; q, then run.sh --resume to reconnect.'
    if tab == 1:
        notice = notice if notice and 'Settings change only' not in notice else ''
    rule(screen, h - 3, 1, w - 2, c)
    put(screen, h - 2, 2, notice, c['warn'] if 'unknown' in notice.lower() or 'unavailable' in notice.lower() else c['muted'], w - 4)
    hints = {0: 'Up/Down select  Left/Right choose  Enter apply',
             1: 'Up/Down select  Left/Right choose  C clear  Enter apply',
             2: 'Up/Down scroll  PgUp/PgDn page  G live  F filter  D details',
             3: 'Stored summaries refresh automatically',
             4: 'R read  V terms  A accept  B back',
             5: 'Counters refresh live'}[tab]
    quit_hint = 'Q stop companion' if integrated else 'Q quit'
    put(screen, h - 1, 2, hints, c['accent'], w - len(quit_hint) - 14)
    put(screen, h - 1, w - len(quit_hint) - 12, '1-6 views  ' + quit_hint, c['muted'])
    screen.refresh()


def draw(screen, monitor, stop_event=None, integrated=False):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.timeout(100)
    try:
        curses.mousemask(curses.BUTTON1_CLICKED)
    except curses.error:
        pass
    colors = palette(screen)
    monitor.recent = deque(maxlen=1000)
    ui = {'filter': 0, 'details': False}
    selected, scroll, tab = 0, 0, 0
    names = list(SETTINGS)
    draft = {name: None for name in names}
    status, status_at, notice = {}, 0, 'Settings change only when you choose a draft and press Enter.'
    future, action = None, None
    sent_setting = sent_value = None
    update_terms = None
    terms_return_tab = 4
    auto_queried, queried_terms_request = False, -1
    last_terms_offer = confirmation_query_token = None
    next_refresh = next_status = 0
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        while stop_event is None or not stop_event.is_set():
            now = time.monotonic()
            if now >= next_refresh:
                try:
                    monitor.refresh()
                except (OSError, ValueError) as error:
                    notice = 'Log read unavailable: ' + type(error).__name__
                next_refresh = now + 1
            if future and future.done():
                try:
                    reply = future.result()
                    if action == 'status' and reply.get('ok'):
                        status, status_at = reply, now
                    elif action == 'update_terms':
                        if reply.get('ok'):
                            update_terms, scroll = reply, 0
                            tab = 4
                            last_terms_offer = (reply['token'], status.get('software_update', {}).get('terms_request', 0))
                            notice = 'A accepts these terms and may let the requested update continue.'
                        else:
                            notice = 'No readable terms yet. Press R, then open Software Update on the Watch.'
                    elif action in ('update_query', 'update_accept_terms'):
                        notice = ('State query sent; waiting for Watch reply.' if action == 'update_query' else
                                  'Acceptance sent; waiting for the Watch to confirm.') if reply.get('ok') else (
                                  'Request blocked or unconfirmed: ' + reply.get('error', 'unknown') + '. No automatic retry.')
                        next_status = 0
                    elif action == 'set':
                        notice = ('Setting sent; verify its effect on the Watch.' if reply.get('ok') else
                                  'Write unconfirmed: ' + reply.get('error', 'unknown outcome') + '. No automatic retry.')
                        if reply.get('ok') and draft.get(sent_setting) == sent_value:
                            draft[sent_setting] = None
                        next_status = 0
                except (OSError, ValueError) as error:
                    if action in ('set', 'update_accept_terms'):
                        notice = 'Write outcome unknown: ' + type(error).__name__ + '. No automatic retry.'
                    else:
                        status_at = 0
                future = None
            ready = bool(status.get('controls_ready') and now - status_at < 6 and not monitor.stopped and not monitor.disconnected)
            fresh = bool(status_at and now - status_at < 6)
            update = status.get('software_update', {})
            token = update.get('token')
            accepted_reply = (token and update.get('acceptance_token') == token
                              and update.get('acceptance_state') == 'reply_success')
            if (update_terms and update_terms.get('token') == token
                    and (accepted_reply or update.get('watch_accepted') is True)):
                update_terms, scroll = None, 0
                if tab == 4:
                    tab = terms_return_tab
                notice = 'Watch accepted the update terms. The preview has closed.'
            automatic = None
            if future is None and ready and update:
                prompt = update.get('terms_request', 0)
                if not auto_queried:
                    automatic = {'command': 'update_query'}
                    auto_queried, queried_terms_request = True, prompt
                elif accepted_reply and confirmation_query_token != token and update.get('watch_accepted') is not True:
                    automatic = {'command': 'update_query'}
                    confirmation_query_token = token
                elif (prompt > queried_terms_request and
                      (not update.get('terms_available') or update.get('watch_accepted') is True)):
                    automatic = {'command': 'update_query'}
                    queried_terms_request = prompt
                elif (token and update.get('terms_available') and update.get('watch_accepted') is not True
                      and update.get('acceptance_state') not in ('sending', 'sent', 'reply_success', 'watch_reported',
                          'watch_notification_received', 'send_outcome_unknown', 'reply_unconfirmed')
                      and last_terms_offer != (token, prompt)):
                    automatic = {'command': 'update_terms'}
                    last_terms_offer = (token, prompt)
                    if update_terms is None:
                        terms_return_tab = tab
                if automatic:
                    action = automatic['command']
                    future = pool.submit(request, monitor.directory / 'control.sock', automatic)
                    notice = 'Loading update terms from the Watch...' if action == 'update_terms' else notice
            if future is None and now >= next_status and (monitor.directory / 'control.sock').exists():
                action = 'status'
                future = pool.submit(request, monitor.directory / 'control.sock', {'command': 'status'})
                next_status = now + 2
            ui['status_at'] = status_at
            render(screen, monitor, status, fresh, ready, selected, draft, notice,
                   tab, scroll, integrated, colors, update_terms, ui)
            key = screen.getch()
            if key in (ord('q'), ord('Q'), 27):
                return
            if key in tuple(ord(str(n)) for n in range(1, len(TABS) + 1)):
                tab, scroll = key - ord('1'), 0
                continue
            if key == 9:
                tab, scroll = (tab + 1) % len(TABS), 0
                continue
            height, width = screen.getmaxyx()
            if height < 22 or width < 72:
                continue
            if key == curses.KEY_MOUSE:
                try:
                    _, mouse_x, mouse_y, _, buttons = curses.getmouse()
                except curses.error:
                    continue
                if tab not in (0, 1) or not buttons & curses.BUTTON1_CLICKED:
                    continue
                index = mouse_y - SETTINGS_TOP[tab] - 2
                value = (False if width - 21 <= mouse_x < width - 14 else
                         True if width - 12 <= mouse_x < width - 6 else None)
                if not 0 <= index < len(names) or value is None or not ready:
                    continue
                selected = index
                draft[names[selected]] = value
                key = curses.KEY_ENTER
            if tab == 4:
                if key in (curses.KEY_UP, curses.KEY_PPAGE):
                    scroll = max(0, scroll - (10 if key == curses.KEY_PPAGE else 1))
                elif key in (curses.KEY_DOWN, curses.KEY_NPAGE) and update_terms:
                    lines = wrap_terms(update_terms['text'], max(1, width - 8))
                    scroll = min(max(0, len(lines) - max(1, height - 14)), scroll + (10 if key == curses.KEY_NPAGE else 1))
                elif key in (ord('b'), ord('B')):
                    update_terms, scroll = None, 0
                    tab = terms_return_tab
                elif key in (ord('r'), ord('R'), ord('v'), ord('V'), ord('a'), ord('A')):
                    if not ready or 'software_update' not in status:
                        notice = 'Update controls unavailable. Reconnect using the updated companion.'
                    elif future:
                        notice = 'Control request busy; try again when it finishes.'
                    else:
                        command = {'command': 'update_query'}
                        if key in (ord('v'), ord('V')):
                            command = {'command': 'update_terms'}
                            if update_terms is None:
                                terms_return_tab = tab
                        elif key in (ord('a'), ord('A')):
                            if (not update_terms or update_terms.get('token') != status['software_update'].get('token')):
                                notice = 'Press V to display the current update terms before accepting.'
                                continue
                            command = {'command': 'update_accept_terms', 'token': update_terms['token']}
                        action = command['command']
                        future = pool.submit(request, monitor.directory / 'control.sock', command)
                        notice = 'Sending update control...' if action != 'update_terms' else 'Loading Watch terms...'
                continue
            if tab in (3, 5):
                continue  # Viewing history or diagnostics never writes Watch settings.
            if tab == 2:
                if key in (ord('f'), ord('F')):
                    ui['filter'], scroll = (ui['filter'] + 1) % len(ACTIVITY_FILTERS), 0
                elif key in (ord('d'), ord('D')):
                    ui['details'] = not ui['details']
                elif key in (ord('g'), ord('G')):
                    scroll = 0
                if key in (curses.KEY_UP, curses.KEY_PPAGE):
                    scroll = min(max(0, len(monitor.recent) - 1), scroll + (3 if key == curses.KEY_PPAGE else 1))
                elif key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                    scroll = max(0, scroll - (3 if key == curses.KEY_NPAGE else 1))
                continue
            if key == curses.KEY_UP:
                selected = (selected - 1) % len(names)
            elif key == curses.KEY_DOWN:
                selected = (selected + 1) % len(names)
            elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
                draft[names[selected]] = key == curses.KEY_RIGHT
            elif key in (ord('c'), ord('C')):
                draft[names[selected]] = None
            elif key in (10, 13, curses.KEY_ENTER):
                name = names[selected]
                if not ready:
                    notice = 'Controls unavailable. Start the updated companion to enable settings.'
                elif draft[name] is None:
                    notice = 'Choose Off or On with Left/Right, then press Enter.'
                elif future:
                    notice = 'Control request busy; try Enter again when it finishes.'
                else:
                    action = 'set'
                    sent_setting, sent_value = name, draft[name]
                    future = pool.submit(request, monitor.directory / 'control.sock',
                                         {'command': 'set', 'setting': name, 'value': draft[name]})
                    notice = 'Sending one settings write...'
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, help='Pin a run; otherwise select the latest once')
    args = parser.parse_args()
    try:
        directory = args.run
        if directory is None:
            runs = Path(__file__).resolve().parent / 'runs'
            candidates = sorted(path for path in runs.iterdir()
                                if path.name[:8].isdigit() and (path / 'events.jsonl').is_file())
            if not candidates:
                raise ValueError('No companion runs found')
            directory = candidates[-1]
        curses.wrapper(draw, Monitor(directory.resolve()))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, curses.error) as error:
        parser.exit(1, 'TUI: %s\n' % error)


if __name__ == '__main__':
    main()
