"""Private local controls for an existing companion; never reads the IDS queue."""
import asyncio
import base64
from contextlib import closing
import json
import os
import plistlib
import socket
import sqlite3
import struct
import time

from apple_codec import PREFS, preferences
from workout_labels import workout_label


SETTINGS = {
    'right_wrist': ('Wear on right wrist', 'com.apple.nano', 'wornOnRightArm', True),
    'invert_ui': ('Invert UI orientation', 'com.apple.nano', 'invertUI', True),
    'time_24_hour': ('24-hour time', '.GlobalPreferences', 'AppleICUForce24HourTime', False),
}


class Operational:
    def __init__(self, flow, directory):
        self.flow, self.path = flow, directory / 'control.sock'
        self.server = None
        self.clients = set()
        self.pending = {}
        self.sending = False
        self.health, self.health_updated = {}, 0

    async def start(self):
        from pairing_store import user_owned
        self.server = await asyncio.start_unix_server(self.handle, path=str(self.path), limit=4096)
        self.path.chmod(0o600)
        user_owned(self.path)
        self.flow.record('operational_controls_ready')

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.path.unlink(missing_ok=True)
        for task in list(self.clients):
            task.cancel()
        await asyncio.gather(*list(self.clients), return_exceptions=True)

    def available(self):
        f = self.flow
        return (f.ids.phase == 'ready' and not f.ids.error and f.peer_info
                and f.local_info_ack and all(lane in f.ids.lanes for lane in ('c', 'd')))

    def snapshot(self):
        f, now = self.flow, time.time()
        rows = {}
        for name, (label, domain, key, two_way) in SETTINGS.items():
            saved = f.store.data.get('preferences_observed', {}).get(domain, {}).get(key, {})
            value = None
            try:
                if saved.get('value_present'):
                    value = plistlib.loads(base64.b64decode(saved['plist_base64'], validate=True))
            except (KeyError, ValueError, plistlib.InvalidFileException):
                pass
            pending = dict(self.pending.get(name, {}))
            if pending and now - pending['sent_at'] > 60 and pending['state'] in ('sent', 'transport_ack', 'application_receipt'):
                pending['state'] = 'effect_unconfirmed'
            # An older saved snapshot cannot confirm a new write.
            if (pending and type(value) is bool and value == pending['value']
                    and saved.get('timestamp', 0) >= pending['timestamp']):
                pending['state'] = 'watch_reported_match'
            rows[name] = {'label': label, 'observed': value if type(value) is bool else None,
                          'observed_at': saved.get('timestamp'), 'two_way': two_way,
                          'request': {k: v for k, v in pending.items() if k in ('value', 'state', 'sent_at')}}
        if now - self.health_updated >= 2:
            self.health_updated = now
            path = f.store.directory / 'health.sqlite3'
            if path.is_file():
                try:
                    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=0.1)) as db:
                        samples, hr = db.execute('SELECT count(*),sum(data_type=5 AND bpm IS NOT NULL) FROM health_records WHERE deleted=0').fetchone()
                        last = db.execute('SELECT start_unix,bpm FROM health_records WHERE data_type=5 AND bpm IS NOT NULL AND deleted=0 ORDER BY start_unix DESC LIMIT 1').fetchone()
                        columns = {r[1] for r in db.execute('PRAGMA table_info(health_sync_state)')}
                        phase = db.execute('SELECT phase' + (',next_changes_at' if 'next_changes_at' in columns else ',NULL') +
                                           ' FROM health_sync_state ORDER BY updated DESC LIMIT 1').fetchone()
                        has_sessions = db.execute("SELECT 1 FROM sqlite_master WHERE name='health_incoming_sessions'").fetchone()
                        session = db.execute('''SELECT state,error_domain,error_code,updated FROM health_incoming_sessions
                            ORDER BY updated DESC LIMIT 1''').fetchone() if has_sessions else None
                        has_workouts = db.execute("SELECT 1 FROM sqlite_master WHERE name='health_workouts'").fetchone()
                        workouts = db.execute('''SELECT activity_type,start_unix,end_unix,duration_seconds,metadata
                            FROM health_workouts WHERE deleted=0 ORDER BY start_unix DESC LIMIT 5''').fetchall() if has_workouts else []
                        workout_count = db.execute('SELECT count(*) FROM health_workouts WHERE deleted=0').fetchone()[0] if has_workouts else 0
                        self.health = {'samples': samples, 'heart_rate_samples': hr or 0,
                                       'latest_hr': list(last) if last else None,
                                       'phase': phase[0] if phase else None,
                                       'next_read_at': phase[1] if phase else None,
                                       'incoming_session': list(session) if session else None,
                                       'workouts': [list(row[:4]) for row in workouts], 'workout_count': workout_count,
                                       'workout_labels': [workout_label(row[0], row[4]) for row in workouts],
                                       'data_applied': False}
                except sqlite3.Error:
                    self.health = {'unavailable': True}
            else:
                self.health = {}
        return {'ok': True, 'controls_ready': self.available(), 'ids_phase': f.ids.phase,
                'ids_lanes': len(f.ids.lanes), 'settings': rows, 'health': self.health,
                'software_update': f.software_update.snapshot()}

    async def set_setting(self, request):
        if set(request) != {'command', 'setting', 'value'}:
            raise ValueError('Expected command, setting and boolean value')
        name, value = request['setting'], request['value']
        if not isinstance(name, str) or name not in SETTINGS or type(value) is not bool:
            raise ValueError('Unsupported setting or non-boolean value')
        if not self.available():
            raise ValueError('Authenticated companion channels are not ready')
        if self.sending:
            raise ValueError('A settings write is already in flight')
        previous = self.pending.get(name)
        if previous and time.time() - previous['sent_at'] < 2:
            raise ValueError('Wait before sending another write to this setting')
        _, domain, key, two_way = SETTINGS[name]
        timestamp = time.time() - 978307200
        values = {key: value}
        if name == 'time_24_hour':
            values['AppleICUForce12HourTime'] = not value
        pending = {'value': value, 'timestamp': timestamp, 'sent_at': time.time(), 'state': 'sending'}
        self.pending[name] = pending
        self.sending = True
        try:
            sent = await asyncio.wait_for(self.flow.ids.send(
                PREFS, 0, preferences(domain, values, two_way=two_way, timestamp=timestamp), flags=4), 8)
            pending.update(state='sent', sequence=sent['sequence'], id=sent['id'])
            self.flow.record('watch_setting_sent', setting=name, sequence=sent['sequence'],
                             watch_effect_confirmed=False)
            return {'ok': True, 'state': 'sent', 'watch_effect_confirmed': False}
        except BaseException:
            # A write may have reached the peer. Never retry it automatically.
            pending['state'] = 'send_outcome_unknown'
            self.flow.record('watch_setting_unconfirmed', setting=name, watch_effect_confirmed=False)
            raise
        finally:
            self.sending = False

    def accept(self, message):
        for name, pending in self.pending.items():
            if (message['event'] == 'ack' and message.get('lane') == 'd'
                    and pending.get('sequence') is not None
                    and message.get('sequence') == pending['sequence']):
                pending['state'] = 'transport_ack'
                self.flow.record('watch_setting_transport_ack', setting=name, watch_effect_confirmed=False)
            elif (message['event'] == 'app_ack' and message.get('topic') == PREFS
                  and pending.get('id') and message.get('peer', '').upper() == pending['id'].upper()):
                pending['state'] = 'application_receipt'
                self.flow.record('watch_setting_application_receipt', setting=name, watch_effect_confirmed=False)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        if len(self.clients) >= 4:
            writer.close()
            return
        self.clients.add(task)
        try:
            uid = struct.unpack('3i', writer.get_extra_info('socket').getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
            if uid not in (0, os.getuid(), int(os.environ.get('SUDO_UID', os.getuid()))):
                raise ValueError('Local user does not own this companion')
            raw = await asyncio.wait_for(reader.readline(), 2)
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError('Expected an object')
            if request == {'command': 'status'}:
                result = self.snapshot()
            elif request.get('command') == 'set':
                result = await self.set_setting(request)
            elif request == {'command': 'update_query'}:
                if not self.available():
                    raise ValueError('Companion channels are not ready')
                result = await self.flow.software_update.send('query')
            elif request == {'command': 'update_terms'}:
                result = self.flow.software_update.terms()
            elif set(request) == {'command', 'token'} and request['command'] == 'update_accept_terms':
                if not self.available() or not isinstance(request['token'], str):
                    raise ValueError('Companion channels or terms are not ready')
                result = await self.flow.software_update.send('accept', request['token'])
            else:
                raise ValueError('Unknown command')
        except (ValueError, TypeError, KeyError, OSError, TimeoutError) as error:
            # Do not reflect untrusted input, internal exceptions, or protocol bodies.
            result = {'ok': False, 'error': type(error).__name__, 'state': 'request_unconfirmed'}
        except Exception:
            result = {'ok': False, 'error': 'ControlError', 'state': 'request_unconfirmed'}
        finally:
            try:
                if not task.cancelling():
                    writer.write(json.dumps(result).encode() + b'\n')
                    await asyncio.wait_for(writer.drain(), 1)
            except (OSError, TimeoutError):
                pass
            finally:
                writer.close()
                self.clients.discard(task)
