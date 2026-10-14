"""Health Restore bootstrap and continuing read sessions over the existing IDS lane."""
from contextlib import closing
import hashlib
import time
import uuid

from apple_codec import field
from health_codec import HEALTH_TOPIC, protect
from health_inbox import binding_key, health_database
from health_receiver import POLL_INTERVAL, tables as receiver_tables, anchor_status
from cryptography.hazmat.primitives import serialization


PROTOCOL_VERSION = 17
MAX_ATTEMPTS = 2
RESPONSE_TIMEOUT = 20.0
# Unlocking Health or preparing its first export can take several minutes.
RESTORE_RESPONSE_TIMEOUT = 180.0
RESTORE_REPLY_MAX_AGE = 600.0


def _uuid_bytes(value):
    return uuid.UUID(value).bytes


def _ensure(database, store, local_public, peer_id):
    database.execute('''CREATE TABLE IF NOT EXISTS health_sync_state (
        pair_key TEXT PRIMARY KEY, local_ids_id TEXT NOT NULL, peer_ids_id TEXT NOT NULL,
        local_key_hash TEXT NOT NULL, peer_key_hash TEXT NOT NULL,
        version INTEGER NOT NULL, persistent_uuid TEXT NOT NULL, health_uuid TEXT NOT NULL,
        source_bundle TEXT NOT NULL, phase TEXT NOT NULL, restore_session TEXT NOT NULL,
        restore_message TEXT, restore_attempts INTEGER NOT NULL DEFAULT 0,
        restore_deadline REAL, changes_session TEXT, changes_message TEXT,
        changes_attempts INTEGER NOT NULL DEFAULT 0, changes_deadline REAL,
        changes_start_date REAL,
        remote_status INTEGER, last_error TEXT, updated REAL NOT NULL)''')
    database.execute('''CREATE TABLE IF NOT EXISTS health_sync_requests (
        pair_key TEXT NOT NULL, purpose TEXT NOT NULL, message_id TEXT NOT NULL,
        session_id TEXT NOT NULL, created REAL NOT NULL, response_used INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (pair_key, purpose, message_id))''')
    columns = {row[1] for row in database.execute('PRAGMA table_info(health_sync_state)')}
    if 'restore_confirmed' not in columns:
        database.execute('ALTER TABLE health_sync_state ADD COLUMN restore_confirmed INTEGER NOT NULL DEFAULT 0')
        # These phases were only reachable after a correlated Restore Finished.
        database.execute('''UPDATE health_sync_state SET restore_confirmed=1
            WHERE phase='restore_remote_finished' OR phase LIKE 'changes_%' ''')
    if 'next_changes_at' not in columns:
        database.execute('ALTER TABLE health_sync_state ADD COLUMN next_changes_at REAL')
    receiver_tables(database)
    peer_public = bytes.fromhex(store.data['ids_peer_public']['A'])
    local_hash, peer_hash = hashlib.sha256(local_public).hexdigest(), hashlib.sha256(peer_public).hexdigest()
    pair_key = binding_key(store, local_public, peer_id)
    database.execute('''UPDATE health_sync_state SET next_changes_at=?
        WHERE pair_key=? AND phase IN ('finished','watch_export_failed','poll_wait','changes_unknown')
        AND next_changes_at>?''', (time.time() + POLL_INTERVAL, pair_key, time.time() + POLL_INTERVAL))
    cursor = database.execute('SELECT * FROM health_sync_state WHERE pair_key=?', (pair_key,))
    columns = tuple(item[0] for item in cursor.description)
    row = cursor.fetchone()
    if row is None:
        identity = store.data.get('health_sync_identities', {}).get(pair_key)
        if identity:
            persistent = str(uuid.UUID(identity['persistent_uuid']))
            health = str(uuid.UUID(identity['health_uuid']))
            source = identity['source_bundle']
        else:
            persistent, health = str(uuid.uuid4()), str(uuid.uuid4())
            source = 'com.apple.health.' + persistent.upper()
            identities = dict(store.data.get('health_sync_identities', {}))
            identities[pair_key] = {'persistent_uuid': persistent, 'health_uuid': health,
                                    'source_bundle': source}
            store.save(health_sync_identities=identities)
        database.execute('''INSERT INTO health_sync_state
            (pair_key, local_ids_id, peer_ids_id, local_key_hash, peer_key_hash, version,
             persistent_uuid, health_uuid, source_bundle, phase, restore_session, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?)''',
            (pair_key, store.data['ids_id'], str(peer_id), local_hash, peer_hash,
             PROTOCOL_VERSION, persistent, health, source, str(uuid.uuid4()), time.time()))
        row = database.execute('SELECT * FROM health_sync_state WHERE pair_key=?', (pair_key,)).fetchone()
    elif row[1:6] != (store.data['ids_id'], str(peer_id), local_hash, peer_hash, PROTOCOL_VERSION):
        raise ValueError('Health state is bound to a different authenticated IDS pair')
    return pair_key, dict(zip(columns, row))


def _persist(database, pair_key, **updates):
    allowed = {'phase', 'restore_message', 'restore_attempts', 'restore_deadline',
               'changes_session', 'changes_message', 'changes_attempts', 'changes_deadline',
               'changes_start_date', 'remote_status', 'last_error'}
    allowed.update(('restore_confirmed', 'next_changes_at'))
    if not updates or set(updates) - allowed:
        raise ValueError('Invalid Health state update')
    updates['updated'] = time.time()
    columns = ', '.join(f'{name}=?' for name in updates)
    database.execute(f'UPDATE health_sync_state SET {columns} WHERE pair_key=?',
                     (*updates.values(), pair_key))


def _state(database, store, local_public, peer_id):
    pair_key, state = _ensure(database, store, local_public, peer_id)
    return pair_key, state


def _restore_plaintext(state):
    restore = (field(1, _uuid_bytes(state['restore_session'])) + field(2, 1) + field(3, 2)
               + field(4, state['source_bundle']))
    envelope = (field(2, state['version']) + field(3, _uuid_bytes(state['persistent_uuid']))
                + field(4, _uuid_bytes(state['health_uuid'])) + field(9, restore))
    return b'\x01\x00\x00' + envelope


def _changes_plaintext(state, status=None):
    changes = (field(2, _uuid_bytes(state['changes_session'])) + field(3, state['changes_start_date'])
               + field(5, 2))
    status = field(1, 4) if status is None else status
    envelope = (field(2, state['version']) + field(3, _uuid_bytes(state['persistent_uuid']))
                + field(4, _uuid_bytes(state['health_uuid'])) + field(7, changes)
                + field(8, status))
    return b'\x02\x00\x00' + envelope


def _crypto(store, local_public):
    private = serialization.load_der_private_key(
        bytes.fromhex(store.data['ids_message_private']['A'][0]), None)
    peer = bytes.fromhex(store.data['ids_peer_public']['A'])
    return private, peer


async def _send_restore(ids, store, local_public, pair_key, state, record):
    with closing(health_database(store)) as database:
        with database:
            current = database.execute('SELECT restore_attempts FROM health_sync_state WHERE pair_key=?',
                                       (pair_key,)).fetchone()[0]
            if current >= MAX_ATTEMPTS:
                return
            deadline = time.time() + RESTORE_RESPONSE_TIMEOUT
            _persist(database, pair_key, phase='restore_prepared',
                     restore_attempts=current + 1, restore_deadline=deadline, last_error=None)
    plaintext = _restore_plaintext(state)
    private, peer = _crypto(store, local_public)
    protected = protect(plaintext, private, local_public, peer)
    sent = await ids.send(HEALTH_TOPIC, None, protected, flags=5, command=0)
    with closing(health_database(store)) as database:
        with database:
            _persist(database, pair_key, phase='restore_sent', restore_message=sent['id'],
                     restore_deadline=time.time() + RESTORE_RESPONSE_TIMEOUT)
            database.execute('''INSERT OR IGNORE INTO health_sync_requests
                (pair_key, purpose, message_id, session_id, created) VALUES (?, ?, ?, ?, ?)''',
                (pair_key, 'restore', sent['id'].upper(), state['restore_session'], time.time()))
    record('health_restore_request_sent', protocol_version=PROTOCOL_VERSION,
           attempt=current + 1, request_id=1, priority=0, ids_flags=5,
           candidate_pairing_uuids_stable=True, watch_acceptance=False,
           outgoing_profile_empty=True, incoming_data_imported=False,
           transport_sequence=sent['sequence'])
    return sent


async def _send_changes(ids, store, local_public, pair_key, state, record):
    with closing(health_database(store)) as database:
        with database:
            row = database.execute('SELECT changes_session, changes_attempts, phase, changes_start_date FROM health_sync_state WHERE pair_key=?',
                                   (pair_key,)).fetchone()
            if row[2] in ('restore_rejected', 'restore_unknown', 'changes_rejected'):
                return
            retry = row[2] == 'changes_sent'
            if retry and row[1] >= MAX_ATTEMPTS:
                return
            changes_session = row[0] if retry else str(uuid.uuid4())
            attempts = row[1] + 1 if retry else 1
            start_date = row[3] if retry else (time.time() - 978307200)
            _persist(database, pair_key, phase='changes_prepared', changes_session=changes_session,
                     changes_attempts=attempts, changes_deadline=time.time() + RESPONSE_TIMEOUT,
                     changes_start_date=start_date)
            state['changes_session'] = changes_session
            state['changes_start_date'] = start_date
            status, anchor_count = anchor_status(database, pair_key, state['health_uuid'], 4)
    plaintext = _changes_plaintext(state, status)
    private, peer = _crypto(store, local_public)
    protected = protect(plaintext, private, local_public, peer)
    sent = await ids.send(HEALTH_TOPIC, None, protected, flags=5, command=0)
    with closing(health_database(store)) as database:
        with database:
            _persist(database, pair_key, phase='changes_sent', changes_message=sent['id'],
                     changes_deadline=time.time() + RESPONSE_TIMEOUT, next_changes_at=None)
            database.execute('''INSERT OR IGNORE INTO health_sync_requests
                (pair_key, purpose, message_id, session_id, created) VALUES (?, ?, ?, ?, ?)''',
                (pair_key, 'changes', sent['id'].upper(), state['changes_session'], time.time()))
    record('health_initial_changes_requested', protocol_version=PROTOCOL_VERSION,
           attempt=attempts, request_id=2, priority=0, ids_flags=5,
           outgoing_change_count=0, status_code=4, anchors_sent=anchor_count,
           incoming_data_imported=False, transport_sequence=sent['sequence'])
    return sent


def observe_health_message(store, local_public, peer_id, result, record):
    decoded = result.get('decoded')
    if decoded is None or not decoded.get('response'):
        return None
    correlated = result.get('correlated_to')
    with closing(health_database(store)) as database:
        with database:
            pair_key = binding_key(store, local_public, peer_id)
            cursor = database.execute('SELECT * FROM health_sync_state WHERE pair_key=?', (pair_key,))
            columns = tuple(item[0] for item in cursor.description)
            row = cursor.fetchone()
            if row is None:
                return None
            state = dict(zip(columns, row))
            request = database.execute('''SELECT purpose, session_id, response_used, created FROM health_sync_requests
                WHERE pair_key=? AND message_id=?''', (pair_key, str(correlated or '').upper())).fetchone()
            if request and request[2]:
                return None
            restore_request = bool(request and request[0] == 'restore')
            if restore_request and (request[1] != state['restore_session'] or state['restore_confirmed']):
                record('health_restore_late_response', reason='superseded_session',
                       health_ack_sent=False, native_progress=False)
                return None
            response_deadline = (request[3] + RESTORE_REPLY_MAX_AGE if restore_request
                                 else state['changes_deadline'] if request and request[0] == 'changes'
                                 and str(correlated).upper() == str(state['changes_message']).upper()
                                 else request[3] + RESPONSE_TIMEOUT if request else None)
            if request and response_deadline is not None and time.time() > response_deadline:
                database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                 (pair_key, str(correlated).upper()))
                record(f'health_{request[0]}_late_response', reason='correlation_timeout',
                       health_ack_sent=False, native_progress=False)
                return None
            recoverable_timeout = (restore_request and state['phase'] == 'restore_unknown'
                                   and state['last_error'] in ('response_timeout', 'response_timeout_after_progress'))
            if request and ((state['phase'] in ('restore_rejected', 'restore_unknown', 'changes_rejected')
                             and not recoverable_timeout)
                            or request[0] == 'changes' and str(correlated).upper() != str(state['changes_message']).upper()):
                database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                 (pair_key, str(correlated).upper()))
                record(f'health_{request[0]}_late_response', reason='terminal_state',
                       health_ack_sent=False, native_progress=False)
                return None
            if decoded.get('message_id') not in (1, 2, 7):
                return None
            if decoded.get('version') != state['version']:
                record('health_response_rejected', reason='protocol_version_mismatch',
                       health_ack_sent=False, native_progress=False)
                return None
            if (decoded.get('persistent'), decoded.get('health')) != (state['persistent_uuid'], state['health_uuid']):
                if request and request[0] in ('restore', 'changes'):
                    purpose = request[0]
                    _persist(database, pair_key, phase=f'{purpose}_rejected', last_error='pairing_uuid_mismatch')
                    database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                     (pair_key, str(correlated).upper()))
                    record(f'health_{purpose}_rejected', reason='pairing_uuid_mismatch',
                           watch_acceptance=False, health_ack_sent=False)
                return None
            if request and request[0] == 'restore':
                restore = decoded.get('restore')
                if restore is None:
                    if decoded.get('changes_present'):
                        _persist(database, pair_key, phase='restore_remote_started')
                        record('health_restore_remote_activity', response_correlated=True,
                               restore_finished=False, changes=len(decoded['changes']))
                    elif decoded.get('status'):
                        _persist(database, pair_key, phase='restore_status_observed',
                                 remote_status=decoded['status']['code'])
                        record('health_restore_status_observed', status_code=decoded['status']['code'],
                               correlated=True, acceptance=False)
                    return None
                if restore['session'] != request[1] or restore['sequence'] != 1:
                    database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                     (pair_key, str(correlated).upper()))
                    _persist(database, pair_key, phase='restore_rejected', last_error='restore_correlation_mismatch')
                    record('health_restore_rejected', reason='restore_correlation_mismatch', watch_acceptance=False)
                elif restore['status'] == 2:
                    # Both attempts refer to one Restore session. A second Finished
                    # reply must not restart Changes after the first one succeeded.
                    database.execute('''UPDATE health_sync_requests SET response_used=1
                        WHERE pair_key=? AND purpose='restore' AND session_id=?''',
                                     (pair_key, state['restore_session']))
                    _persist(database, pair_key, phase='restore_remote_finished', remote_status=2,
                             restore_confirmed=1, last_error=None)
                    record('health_restore_accepted', correlated=True, remote_status=2,
                           pairing_binding_confirmed=True, incoming_data_imported=False,
                           response_age_seconds=round(time.time() - request[3], 1),
                           recovered_after_timeout=recoverable_timeout)
                    state['phase'] = 'restore_remote_finished'
                    state['changes_session'] = state['changes_session'] or str(uuid.uuid4())
                    return pair_key, state
                elif restore['status'] == 1:
                    _persist(database, pair_key, phase='restore_remote_started', remote_status=1)
                    record('health_restore_remote_activity', response_correlated=True,
                           restore_finished=False, status_code=1)
                elif restore['status'] == 3:
                    database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                     (pair_key, str(correlated).upper()))
                    _persist(database, pair_key, phase='restore_rejected', remote_status=3,
                             last_error='watch_restore_aborted')
                    record('health_restore_rejected', reason='watch_restore_aborted',
                           remote_status=3, watch_acceptance=False)
                else:
                    _persist(database, pair_key, phase='restore_status_observed',
                             remote_status=restore['status'], last_error='unknown_restore_status')
                    record('health_restore_status_observed', status_code=restore['status'],
                           correlated=True, acceptance=False)
                return None
            if request and request[0] == 'changes':
                if decoded.get('changes_present'):
                    _persist(database, pair_key, phase='changes_received')
                    record('health_changes_received', correlated=True, changes=len(decoded['changes']),
                           records_staged=True, native_progress_held=True, health_ack_sent=False)
                elif decoded.get('status'):
                    code = decoded['status']['code']
                    database.execute('UPDATE health_sync_requests SET response_used=1 WHERE pair_key=? AND message_id=?',
                                     (pair_key, str(correlated).upper()))
                    incoming_phase = state['phase'] in ('receiving', 'finished', 'watch_export_failed')
                    next_phase = state['phase'] if incoming_phase else 'watch_stream_waiting'
                    _persist(database, pair_key, phase=next_phase if code == 1 else 'changes_rejected',
                             remote_status=code,
                             next_changes_at=(state['next_changes_at'] if incoming_phase else time.time() + POLL_INTERVAL)
                                             if code == 1 else None,
                             last_error=('watch_export_failed' if state['phase'] == 'watch_export_failed' else None)
                                        if code == 1 else 'watch_status_requires_review')
                    record('health_changes_status_observed', status_code=decoded['status']['code'],
                           correlated=True, data_applied=False, health_ack_sent=False)
    return None


def next_health_timeout(ids, store, local_public, peer_id, ready):
    if not ready or ids.error or ids.phase != 'ready' or not all(lane in ids.lanes for lane in ('c', 'd')):
        return None
    with closing(health_database(store)) as database:
        with database:
            _ensure(database, store, local_public, peer_id)
        row = database.execute('''SELECT phase, restore_deadline, restore_attempts,
            changes_deadline, changes_attempts,next_changes_at,restore_confirmed FROM health_sync_state WHERE pair_key=?''',
            (binding_key(store, local_public, peer_id),)).fetchone()
    if row is None or row[0] in ('prepared', 'restore_remote_finished', 'restore_prepared', 'changes_prepared'):
        return 0.0
    if row[0] in ('restore_sent', 'restore_remote_started', 'restore_status_observed'):
        deadline = row[1]
    elif row[0] in ('changes_sent', 'changes_received', 'changes_status_observed', 'receiving'):
        deadline = row[3]
    elif row[6] and row[0] not in ('restore_rejected', 'restore_unknown', 'changes_rejected'):
        deadline = row[5]
    else:
        return None
    return max(0.0, deadline - time.time()) if deadline is not None else 0.0


async def advance_health(ids, store, local_public, peer_id, ready, record):
    if not ready or ids.error or ids.phase != 'ready' or not all(lane in ids.lanes for lane in ('c', 'd')):
        return None
    with closing(health_database(store)) as database:
        with database:
            pair_key, state = _state(database, store, local_public, peer_id)
            now = time.time()
            phase = state['phase']
            if phase == 'restore_prepared':
                _persist(database, pair_key, phase='restore_unknown', last_error='send_outcome_unknown')
                record('health_restore_unconfirmed', reason='send_outcome_unknown',
                       attempts=state['restore_attempts'], watch_acceptance=False)
                return None
            if phase == 'changes_prepared':
                _persist(database, pair_key, phase='changes_unknown', last_error='send_outcome_unknown',
                         next_changes_at=now + POLL_INTERVAL)
                record('health_changes_unconfirmed', reason='send_outcome_unknown',
                       attempts=state['changes_attempts'], health_ack_sent=False)
                return None
            if phase in ('restore_remote_started', 'restore_status_observed'):
                if state['restore_deadline'] is None or now >= state['restore_deadline']:
                    _persist(database, pair_key, phase='restore_unknown', last_error='response_timeout_after_progress')
                    record('health_restore_unconfirmed', reason='bounded_timeout_after_progress',
                           attempts=state['restore_attempts'], watch_acceptance=False)
                return None
            if phase in ('changes_received', 'changes_status_observed'):
                if state['changes_deadline'] is None or now >= state['changes_deadline']:
                    _persist(database, pair_key, phase='changes_unknown', last_error='response_timeout_after_progress',
                             next_changes_at=now + POLL_INTERVAL)
                    record('health_changes_unconfirmed', reason='bounded_timeout_after_progress',
                           attempts=state['changes_attempts'], health_ack_sent=False)
                return None
            if phase in ('restore_rejected', 'restore_unknown', 'changes_rejected'):
                return None
            if phase == 'receiving':
                # Incoming progress refreshes its idle deadline. Do not start
                # another export while the Watch is still sending this one.
                if state['changes_deadline'] is not None and now < state['changes_deadline']:
                    return None
                _persist(database, pair_key, phase='poll_wait',
                         next_changes_at=now + POLL_INTERVAL, last_error='incoming_idle_timeout')
                record('health_incoming_idle', read_interval_seconds=POLL_INTERVAL,
                       health_ack_sent=False)
                return None
            if state['restore_confirmed'] and phase in (
                    'changes_unknown', 'watch_stream_waiting', 'finished', 'watch_export_failed', 'poll_wait'):
                due = state['next_changes_at']
                if due is not None and now < due:
                    return None
                # A fresh read session resumes the same confirmed store. This is
                # not a Restore replay or a resend of a partially received batch.
                phase = 'poll_wait'
            if phase == 'prepared' and state['restore_attempts']:
                _persist(database, pair_key, phase='restore_unknown', last_error='send_outcome_unknown')
                record('health_restore_unconfirmed', reason='send_outcome_unknown',
                       attempts=state['restore_attempts'], watch_acceptance=False)
                return None
            if phase == 'restore_sent' and state['restore_deadline'] is None:
                _persist(database, pair_key, phase='restore_unknown', last_error='missing_deadline')
                record('health_restore_unconfirmed', reason='missing_deadline',
                       attempts=state['restore_attempts'], watch_acceptance=False)
                return None
            if phase == 'changes_sent' and state['changes_deadline'] is None:
                _persist(database, pair_key, phase='changes_unknown', last_error='missing_deadline',
                         next_changes_at=now + POLL_INTERVAL)
                record('health_changes_unconfirmed', reason='missing_deadline',
                       attempts=state['changes_attempts'], health_ack_sent=False)
                return None
            if phase == 'restore_sent' and state['restore_deadline'] is not None \
                    and now >= state['restore_deadline'] and state['restore_attempts'] >= MAX_ATTEMPTS:
                _persist(database, pair_key, phase='restore_unknown', last_error='response_timeout')
                record('health_restore_unconfirmed', reason='bounded_timeout',
                       attempts=state['restore_attempts'], watch_acceptance=False)
                return None
            if phase == 'changes_sent' and state['changes_deadline'] is not None \
                    and now >= state['changes_deadline'] and state['changes_attempts'] >= MAX_ATTEMPTS:
                _persist(database, pair_key, phase='changes_unknown', last_error='response_timeout',
                         next_changes_at=now + POLL_INTERVAL)
                record('health_changes_unconfirmed', reason='bounded_timeout',
                       attempts=state['changes_attempts'], health_ack_sent=False)
                return None
            if phase == 'restore_remote_finished':
                pass
            elif phase == 'restore_sent' and now < state['restore_deadline']:
                return None
            elif phase == 'changes_sent' and now < state['changes_deadline']:
                return None
        if phase == 'restore_remote_finished':
            return await _send_changes(ids, store, local_public, pair_key, state, record)
        if phase == 'poll_wait':
            return await _send_changes(ids, store, local_public, pair_key, state, record)
        if phase == 'changes_sent' and state['changes_attempts'] < MAX_ATTEMPTS:
            return await _send_changes(ids, store, local_public, pair_key, state, record)
        if phase in ('prepared', 'restore_sent'):
            if state['restore_deadline'] is not None and now < state['restore_deadline']:
                return None
            if state['restore_attempts'] < MAX_ATTEMPTS:
                return await _send_restore(ids, store, local_public, pair_key, state, record)
    return None
