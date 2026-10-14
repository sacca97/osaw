"""Durable Health receive progress and native request replies; no outgoing samples."""
from contextlib import closing
import time
import uuid

from apple_codec import field, one, protobuf
from health_codec import HEALTH_TOPIC, protect
from health_inbox import health_database
from cryptography.hazmat.primitives import serialization

POLL_INTERVAL = 20.0
ACTIVE_TRANSFER_IDLE_TIMEOUT = 120.0
SUPPORTED = {2: 1, 4: 2, 11: 10, 13: 12}  # native entity -> legacy object type


def tables(db):
    db.execute('''CREATE TABLE IF NOT EXISTS health_received_progress (
        pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, schema TEXT NOT NULL,
        entity INTEGER NOT NULL, received INTEGER NOT NULL DEFAULT 0,
        expected_sequence INTEGER NOT NULL DEFAULT 0, identity_raw BLOB,
        PRIMARY KEY(pair_key,health_uuid,schema,entity))''')
    db.execute('''CREATE TABLE IF NOT EXISTS health_incoming_sessions (
        pair_key TEXT NOT NULL, session TEXT NOT NULL, start_date REAL NOT NULL,
        state TEXT NOT NULL, remote_status INTEGER, error_domain TEXT, error_code INTEGER,
        updated REAL NOT NULL, PRIMARY KEY(pair_key,session))''')
    db.execute('''CREATE TABLE IF NOT EXISTS health_empty_exports (
        pair_key TEXT NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL,
        PRIMARY KEY(pair_key,request_id))''')
    db.execute('CREATE TABLE IF NOT EXISTS health_receiver_meta (key TEXT PRIMARY KEY,value INTEGER NOT NULL)')
    if db.execute("SELECT value FROM health_receiver_meta WHERE key='bool_fields'").fetchone() != (2,):
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='health_change_records'").fetchone():
            for row in db.execute('''SELECT pair_key,message_id,digest,change_index,raw FROM health_change_records
                WHERE state='speculative_stored' ''').fetchall():
                complete = one(protobuf(row[4]), 8)
                db.execute('''UPDATE health_change_records SET complete=?,state='held',reason='field_mapping_corrected'
                    WHERE pair_key=? AND message_id=? AND digest=? AND change_index=?''', (complete, *row[:4]))
        db.execute('UPDATE health_received_progress SET expected_sequence=0 WHERE received=0')
        db.execute("INSERT OR REPLACE INTO health_receiver_meta VALUES ('bool_fields',2)")


def anchor_status(db, pair_key, health_uuid, code):
    result = field(1, code)
    rows = db.execute('''SELECT entity,received,identity_raw FROM health_received_progress
        WHERE pair_key=? AND health_uuid=? AND received>0 ORDER BY schema,entity''',
                      (pair_key, health_uuid)).fetchall()
    for entity, received, identity in rows:
        anchor = field(1, SUPPORTED[entity]) + field(2, received)
        if identity is not None:
            anchor += field(3, identity)
        result += field(2, anchor)
    return result, len(rows)


def apply_changes(db, pair_key, health_uuid, result):
    applied = speculative = held = 0
    for index, change in enumerate(result['decoded']['changes']):
        key = (pair_key, result['message_id'], result['digest'], index)
        existing = db.execute('''SELECT state FROM health_change_records
            WHERE pair_key=? AND message_id=? AND digest=? AND change_index=?''', key).fetchone()
        if not existing or existing[0] in ('committed', 'speculative_stored', 'partial'):
            continue
        entity, schema = change['entity'], change['schema']
        reason = None
        if entity not in SUPPORTED or schema:
            reason = 'unsupported_entity_or_schema'
        elif db.execute('SELECT 1 FROM health_record_conflicts WHERE pair_key=? AND message_id=? LIMIT 1',
                        (pair_key, result['message_id'])).fetchone():
            reason = 'record_conflict'
        else:
            db.execute('''INSERT OR IGNORE INTO health_received_progress
                (pair_key,health_uuid,schema,entity,identity_raw) VALUES (?,?,?,?,?)''',
                       (pair_key, health_uuid, schema, entity, change['identity_raw']))
            received, expected = db.execute('''SELECT received,expected_sequence FROM health_received_progress
                WHERE pair_key=? AND health_uuid=? AND schema=? AND entity=?''',
                                           (pair_key, health_uuid, schema, entity)).fetchone()
            sequence = change['sequence']
            if sequence is not None and (type(sequence) is not int or sequence < 0
                                         or sequence >= 1 << 63 or sequence not in (0, expected)):
                reason = 'sequence_gap'
            # Native speculative changes bypass range/dependency validation and
            # never advance received anchors (HDDaemonSyncEngine 23T240).
            elif not change['speculative']:
                start, end = change['start'], change['end']
                if any(type(v) is not int or not 0 <= v < 1 << 63 for v in (start, end)) or start > end:
                    reason = 'invalid_anchor_range'
                elif start > received:
                    reason = 'anchor_gap'
                else:
                    for dependency in change['dependencies']:
                        if dependency['entity'] is None:
                            reason = 'unknown_dependency_entity'
                            break
                        row = db.execute('''SELECT received FROM health_received_progress
                            WHERE pair_key=? AND health_uuid=? AND schema=? AND entity=?''',
                                         (pair_key, health_uuid, dependency['schema'], dependency['entity'])).fetchone()
                        if (row[0] if row else 0) < dependency['anchor']:
                            reason = 'dependency_gap'
                            break
            if reason is None:
                done = change['complete'] == 1 or sequence is None
                next_sequence = 0 if done else sequence + 1
                committed = done and not change['speculative']
                db.execute('''UPDATE health_received_progress SET received=?,expected_sequence=?
                    WHERE pair_key=? AND health_uuid=? AND schema=? AND entity=?''',
                           (max(received, change['end']) if committed else received, next_sequence,
                            pair_key, health_uuid, schema, entity))
                state = 'speculative_stored' if change['speculative'] else 'committed' if committed else 'partial'
                db.execute('''UPDATE health_change_records SET state=?,reason=NULL
                    WHERE pair_key=? AND message_id=? AND digest=? AND change_index=?''', (state, *key))
                applied += int(committed)
                speculative += int(change['speculative'])
        if reason:
            held += 1
            db.execute('''UPDATE health_change_records SET reason=?
                WHERE pair_key=? AND message_id=? AND digest=? AND change_index=?''', (reason, *key))
    return applied, speculative, held


async def send_data(ids, store, local_public, plaintext, **kwargs):
    private = serialization.load_der_private_key(bytes.fromhex(store.data['ids_message_private']['A'][0]), None)
    peer = bytes.fromhex(store.data['ids_peer_public']['A'])
    return await ids.send(HEALTH_TOPIC, None, protect(plaintext, private, local_public, peer), command=0, **kwargs)


async def receive_changes(ids, store, local_public, result, message, record):
    decoded = result.get('decoded')
    if not decoded or decoded.get('response') or decoded.get('message_id') not in (2, 7):
        return None
    pair_key = result['pair_key']
    change_set = decoded.get('change_set')
    empty_export = False
    with closing(health_database(store)) as db:
        with db:
            tables(db)
            bound = db.execute('''SELECT persistent_uuid,health_uuid,restore_confirmed FROM health_sync_state
                WHERE pair_key=?''', (pair_key,)).fetchone()
            if not bound or not bound[2] or (decoded['persistent'], decoded['health']) != bound[:2]:
                record('health_incoming_held', reason='unconfirmed_pairing_binding', health_ack_sent=False)
                return None
            if change_set:
                session, start = change_set['session'], change_set['start_date']
                if session is None or start is None or start <= 0 or change_set['status'] not in (1, 2, 3):
                    record('health_incoming_held', reason='invalid_session_header', health_ack_sent=False)
                    return None
                previous = db.execute('SELECT start_date FROM health_incoming_sessions WHERE pair_key=? AND session=?',
                                      (pair_key, session)).fetchone()
                if previous and previous[0] != start:
                    record('health_incoming_held', reason='session_start_mismatch', health_ack_sent=False)
                    return None
                error = change_set.get('error', {})
                phase = {1: 'receiving', 2: 'finished', 3: 'watch_export_failed'}[change_set['status']]
                db.execute('''INSERT INTO health_incoming_sessions VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(pair_key,session) DO UPDATE SET state=excluded.state,
                    remote_status=excluded.remote_status,error_domain=excluded.error_domain,
                    error_code=excluded.error_code,updated=excluded.updated''',
                           (pair_key, session, start, phase, change_set['status'],
                            error.get('domain'), error.get('code'), time.time()))
                applied, speculative, held = apply_changes(db, pair_key, decoded['health'], result)
                db.execute('''UPDATE health_sync_state SET phase=?,next_changes_at=?,changes_deadline=?,
                    last_error=?,updated=? WHERE pair_key=?''',
                           (phase, time.time() + POLL_INTERVAL if phase != 'receiving' else None,
                            time.time() + ACTIVE_TRANSFER_IDLE_TIMEOUT,
                            'watch_export_failed' if phase == 'watch_export_failed' else None,
                            time.time(), pair_key))
                record('health_incoming_progress', session_status=change_set['status'],
                       committed_changes=applied, speculative_changes=speculative, held_changes=held,
                       error_domain=error.get('domain'), error_code=error.get('code'),
                       data_applied=bool(applied), health_ack_sent=False)
            status, anchor_count = anchor_status(db, pair_key, decoded['health'], 1)
            if decoded.get('status', {}).get('code') in (4, 5):
                # The Watch also asks for our changes. This companion owns no
                # outgoing Health samples, so finish that direction explicitly.
                cursor = db.execute('INSERT OR IGNORE INTO health_empty_exports VALUES (?,?,?)',
                                    (pair_key, message['id'], 'prepared'))
                empty_export = cursor.rowcount == 1
    # A normal native response accepts a delivered request. Its anchor map alone
    # acknowledges committed entity progress. Speculative/opaque data add no anchors.
    sent = None
    envelope = (field(2, decoded['version']) + field(3, uuid.UUID(decoded['persistent']).bytes)
                + field(4, uuid.UUID(decoded['health']).bytes) + field(8, status))
    if message.get('flags', 0) & 1:
        sent = await send_data(ids, store, local_public, decoded['message_id'].to_bytes(2, 'little') + envelope,
                               peer=message['id'], response=True)
        record('health_request_replied', received_anchor_count=anchor_count, status_code=1,
               health_ack_sent=bool(anchor_count), transport_sequence=sent['sequence'])
    if empty_export:
        changes = field(2, uuid.uuid4().bytes) + field(3, time.time() - 978307200) + field(5, 2)
        sent = await send_data(ids, store, local_public, b'\x02\x00\x00' + envelope + field(7, changes), flags=5)
        with closing(health_database(store)) as db:
            with db:
                db.execute('UPDATE health_empty_exports SET state=? WHERE pair_key=? AND request_id=?',
                           ('sent', pair_key, message['id']))
        record('health_empty_export_finished', outgoing_samples=0, received_anchor_count=anchor_count,
               transport_sequence=sent['sequence'])
    return sent
