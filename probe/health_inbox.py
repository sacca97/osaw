"""Private, receive-only Health staging. Storing bytes never advances sync anchors."""
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from health_codec import MAX_ENVELOPE, unprotect
from health_messages import decode_health_frame
from pairing_store import user_owned


MAX_STAGED_BYTES = 64 * 1024 * 1024


def reset_health_data(store, record):
    """Discard session Health data; keep only authenticated-pair protocol identity."""
    path = store.directory / 'health.sqlite3'
    if path.exists():
        with closing(health_database(store)) as database:
            if database.execute("SELECT 1 FROM sqlite_master WHERE name='health_sync_state'").fetchone():
                identities = dict(store.data.get('health_sync_identities', {}))
                for pair, persistent, health, source in database.execute(
                        'SELECT pair_key,persistent_uuid,health_uuid,source_bundle FROM health_sync_state'):
                    identities[pair] = {'persistent_uuid': persistent, 'health_uuid': health,
                                        'source_bundle': source}
                store.save(health_sync_identities=identities)
    removed = 0
    for suffix in ('-wal', '-shm', '-journal', ''):
        candidate = path.with_name(path.name + suffix)
        if candidate.exists():
            candidate.unlink()
            removed += 1
    record('health_session_reset', files_removed=removed, samples_retained=False)


def binding_key(store, local_public, peer_id):
    peer_hex = store.data.get('ids_peer_public', {}).get('A')
    peer = bytes.fromhex(peer_hex) if peer_hex else b''
    material = b'health-sync-v1\0' + store.data['ids_id'].encode() + str(peer_id or '').encode()
    material += hashlib.sha256(local_public).digest() + hashlib.sha256(peer).digest()
    return hashlib.sha256(material).hexdigest()


def health_database(store):
    path = store.directory / 'health.sqlite3'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Health inbox must be a private regular file')
    finally:
        os.close(fd)
    user_owned(path)
    database = sqlite3.connect(path, timeout=5)
    database.execute('PRAGMA synchronous=FULL')
    return database


def receive_health(store, local_public, message, record, peer_id=None):
    payload = message['payload']
    if not isinstance(payload, bytes) or len(payload) > MAX_ENVELOPE:
        record('health_message_held', reason='envelope_size_limit', data_applied=False)
        return
    plaintext, error = None, None
    try:
        private = serialization.load_der_private_key(
            bytes.fromhex(store.data['ids_message_private']['A'][1]), None)
        peer = bytes.fromhex(store.data['ids_peer_public']['A'])
        plaintext = unprotect(payload, private, peer, local_public)
        state = 'decrypted_pending_protocol'
    except KeyError:
        state = 'pending_identity'
    except (ValueError, TypeError, InvalidSignature) as failure:
        state, error = 'rejected_envelope', type(failure).__name__
    # Untyped Alloy data replies correlate through the peer response identifier;
    # parse_application's protobuf response bit is absent for COMMAND_DATA.
    response = bool(message.get('peer'))
    decoded = None
    if plaintext is not None:
        try:
            decoded = decode_health_frame(plaintext, response=response)
            state = 'decoded_pending_sync_validation'
        except (ValueError, TypeError, OverflowError) as failure:
            state, error = 'decrypted_pending_protocol', type(failure).__name__
    digest = hashlib.sha256(payload).hexdigest()
    pair_key = binding_key(store, local_public, peer_id)
    held_reasons = set()
    with closing(health_database(store)) as database:
        with database:
            if decoded is not None and decoded.get('persistent') is not None:
                has_binding = database.execute("SELECT 1 FROM sqlite_master WHERE name='health_sync_state'").fetchone()
                expected = database.execute('SELECT persistent_uuid,health_uuid FROM health_sync_state WHERE pair_key=?',
                                            (pair_key,)).fetchone() if has_binding else None
                if expected and (decoded['persistent'], decoded['health']) != expected:
                    decoded, state, error = None, 'rejected_pairing_binding', 'pairing_uuid_mismatch'
            database.execute('''CREATE TABLE IF NOT EXISTS inbox (
                message_id TEXT NOT NULL, digest TEXT NOT NULL, received REAL NOT NULL,
                response INTEGER NOT NULL, command INTEGER, message_type INTEGER,
                state TEXT NOT NULL, error TEXT, encrypted BLOB NOT NULL, plaintext BLOB,
                PRIMARY KEY (message_id, digest))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_change_records (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, message_id TEXT NOT NULL,
                digest TEXT NOT NULL, change_index INTEGER NOT NULL, entity INTEGER, sequence INTEGER,
                start_anchor INTEGER, end_anchor INTEGER, complete INTEGER, dependencies TEXT NOT NULL,
                state TEXT NOT NULL, reason TEXT, raw BLOB NOT NULL,
                PRIMARY KEY (pair_key, message_id, digest, change_index))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_entity_records (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, entity INTEGER NOT NULL,
                object_key TEXT NOT NULL, state TEXT NOT NULL, message_id TEXT NOT NULL, raw BLOB NOT NULL,
                PRIMARY KEY (pair_key, health_uuid, entity, object_key))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_record_conflicts (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, entity INTEGER NOT NULL,
                object_key TEXT NOT NULL, message_id TEXT NOT NULL, raw BLOB NOT NULL,
                PRIMARY KEY (pair_key, health_uuid, entity, object_key, message_id))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_plugin_records (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, schema TEXT NOT NULL,
                entity INTEGER NOT NULL, object_key TEXT NOT NULL, message_id TEXT NOT NULL,
                raw BLOB NOT NULL, PRIMARY KEY(pair_key,health_uuid,schema,entity,object_key))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_records (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, sample_uuid TEXT NOT NULL,
                data_type INTEGER, start_unix REAL NOT NULL, end_unix REAL NOT NULL,
                bpm REAL, canonical REAL, original REAL, original_unit TEXT, source_bundle TEXT,
                created_unix REAL, external_sync_code INTEGER, metadata BLOB, raw BLOB NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL, message_id TEXT NOT NULL,
                PRIMARY KEY (pair_key, health_uuid, sample_uuid))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_workouts (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, workout_uuid TEXT NOT NULL,
                activity_type INTEGER, start_unix REAL NOT NULL, end_unix REAL NOT NULL,
                duration_seconds REAL, energy_canonical REAL, distance_canonical REAL,
                basal_energy_canonical REAL, source_bundle TEXT, metadata BLOB, raw BLOB NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL, message_id TEXT NOT NULL,
                PRIMARY KEY(pair_key,health_uuid,workout_uuid))''')
            database.execute('''CREATE TABLE IF NOT EXISTS health_deletions (
                pair_key TEXT NOT NULL, health_uuid TEXT NOT NULL, sample_uuid TEXT NOT NULL,
                message_id TEXT NOT NULL, data_type INTEGER, start_unix REAL NOT NULL,
                end_unix REAL NOT NULL, raw BLOB NOT NULL,
                PRIMARY KEY (pair_key, health_uuid, sample_uuid))''')
            exists = database.execute('SELECT 1 FROM inbox WHERE message_id=? AND digest=?',
                                      (message['id'], digest)).fetchone()
            if decoded is not None and database.execute('SELECT 1 FROM inbox WHERE message_id=? AND digest<>? LIMIT 1',
                                                       (message['id'], digest)).fetchone():
                decoded, state, error = None, 'rejected_message_reuse', 'message_id_payload_changed'
            size = database.execute('SELECT COALESCE(SUM(length(encrypted) + COALESCE(length(plaintext),0)),0) FROM inbox').fetchone()[0]
            if not exists and size + len(payload) + len(plaintext or b'') > MAX_STAGED_BYTES:
                record('health_message_held', reason='inbox_size_limit', data_applied=False)
                return
            database.execute('''INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(message_id, digest) DO UPDATE SET
                state=excluded.state, error=excluded.error, plaintext=excluded.plaintext
                WHERE inbox.state='pending_identity' ''',
                (message['id'], digest, time.time(), response,
                 message.get('command'), message.get('type'), state, error, payload, plaintext))
            if decoded is not None:
                database.execute('''CREATE TABLE IF NOT EXISTS heart_rate_observations (
                    persistent_uuid TEXT NOT NULL, health_uuid TEXT NOT NULL, sample_uuid TEXT NOT NULL,
                    start_unix REAL NOT NULL, end_unix REAL NOT NULL, bpm REAL NOT NULL,
                    canonical REAL, original REAL, original_unit TEXT, message_id TEXT NOT NULL,
                    PRIMARY KEY (persistent_uuid, health_uuid, sample_uuid))''')
                for sample in decoded['samples']:
                    database.execute('''INSERT OR IGNORE INTO heart_rate_observations
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (decoded['persistent'], decoded['health'], sample['uuid'],
                         sample['start_unix'], sample['end_unix'], sample['bpm'],
                         sample['canonical'], sample['original'], sample['original_unit'], message['id']))
                persistent, health = decoded.get('persistent'), decoded.get('health')
                for index, change in enumerate(decoded.get('changes', [])):
                    reason = ('unsupported_schema' if change['schema'] else 'workout_summary_only' if change['entity'] == 5 else
                              'unsupported_entity' if change['entity'] not in (2, 4, 11, 13) else None)
                    if reason is None:
                        # Durability precedes the receiver's actual sequence,
                        # range and dependency checks; staging alone advances nothing.
                        reason = 'pending_receive_validation'
                    held_reasons.add(reason)
                    dependencies = json.dumps([{k: v for k, v in dependency.items() if k != 'identity_raw'}
                                               for dependency in change['dependencies']],
                                              sort_keys=True, separators=(',', ':'))
                    database.execute('''INSERT OR IGNORE INTO health_change_records VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (pair_key, health, message['id'], digest, index, change['entity'],
                         change['sequence'], change['start'], change['end'],
                         int(change['complete']) if type(change['complete']) is int else None,
                         dependencies, 'held', reason, change['raw']))
                    for raw_object in change['objects'] if change['entity'] is not None else ():
                        object_key = hashlib.sha256(raw_object).hexdigest()
                        if change['schema']:
                            database.execute('''INSERT OR IGNORE INTO health_plugin_records
                                VALUES (?,?,?,?,?,?,?)''',
                                (pair_key, health, change['schema'], change['entity'], object_key, message['id'], raw_object))
                            continue
                        existing = database.execute('''SELECT raw FROM health_entity_records
                            WHERE pair_key=? AND health_uuid=? AND entity=? AND object_key=?''',
                            (pair_key, health, change['entity'], object_key)).fetchone()
                        if existing is None:
                            database.execute('''INSERT INTO health_entity_records VALUES
                                (?, ?, ?, ?, 'staged', ?, ?)''',
                                (pair_key, health, change['entity'], object_key, message['id'], raw_object))
                        elif existing[0] != raw_object:
                            # A hash-key collision is retained separately; never overwrite authenticated bytes.
                            database.execute('''INSERT OR IGNORE INTO health_record_conflicts VALUES
                                (?, ?, ?, ?, ?, ?)''',
                                (pair_key, health, change['entity'], object_key, message['id'], raw_object))
                    for sample in change['samples']:
                        deleted_before = database.execute('''SELECT 1 FROM health_deletions
                            WHERE pair_key=? AND health_uuid=? AND sample_uuid=? LIMIT 1''',
                            (pair_key, health, sample['uuid'])).fetchone()
                        existing = database.execute('''SELECT raw FROM health_records
                            WHERE pair_key=? AND health_uuid=? AND sample_uuid=?''',
                            (pair_key, health, sample['uuid'])).fetchone()
                        if existing is not None:
                            if existing[0] != sample['raw']:
                                database.execute('''INSERT OR IGNORE INTO health_record_conflicts VALUES
                                    (?, ?, ?, ?, ?, ?)''',
                                    (pair_key, health, change['entity'], sample['uuid'], message['id'], sample['raw']))
                            continue
                        database.execute('''INSERT INTO health_records
                            (pair_key, health_uuid, sample_uuid, data_type, start_unix, end_unix,
                             bpm, canonical, original, original_unit, source_bundle, created_unix,
                             external_sync_code, metadata, raw, deleted, state, message_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged', ?)
                            ON CONFLICT(pair_key, health_uuid, sample_uuid) DO NOTHING''',
                            (pair_key, health, sample['uuid'], sample['data_type'],
                             sample['start_unix'], sample['end_unix'], sample.get('bpm'),
                             sample.get('canonical'), sample.get('original'), sample.get('original_unit'),
                             sample.get('source_bundle'), sample.get('created_unix'),
                             sample.get('external_sync_code'), sample.get('metadata'), sample['raw'],
                             int(deleted_before is not None), message['id']))
                    for deleted in change['deleted']:
                        database.execute('''INSERT INTO health_deletions VALUES
                            (?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(pair_key, health_uuid, sample_uuid) DO UPDATE SET
                                message_id=excluded.message_id, data_type=excluded.data_type,
                                start_unix=excluded.start_unix, end_unix=excluded.end_unix,
                                raw=excluded.raw''',
                            (pair_key, health, deleted['uuid'], message['id'], deleted['data_type'],
                             deleted['start_unix'], deleted['end_unix'], deleted['raw']))
                        database.execute('''UPDATE health_records SET deleted=1, state='staged'
                            WHERE pair_key=? AND health_uuid=? AND sample_uuid=?''',
                            (pair_key, health, deleted['uuid']))
                        database.execute('''UPDATE health_workouts SET deleted=1
                            WHERE pair_key=? AND health_uuid=? AND workout_uuid=?''',
                            (pair_key, health, deleted['uuid']))
                    for workout in change['workouts']:
                        existing = database.execute('''SELECT raw FROM health_workouts
                            WHERE pair_key=? AND health_uuid=? AND workout_uuid=?''',
                            (pair_key, health, workout['uuid'])).fetchone()
                        if existing:
                            if existing[0] != workout['raw']:
                                database.execute('INSERT OR IGNORE INTO health_record_conflicts VALUES (?,?,?,?,?,?)',
                                    (pair_key, health, 5, workout['uuid'], message['id'], workout['raw']))
                            continue
                        deleted_before = database.execute('''SELECT 1 FROM health_deletions
                            WHERE pair_key=? AND health_uuid=? AND sample_uuid=?''',
                            (pair_key, health, workout['uuid'])).fetchone()
                        database.execute('''INSERT INTO health_workouts VALUES
                            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'staged',?)''',
                            (pair_key, health, workout['uuid'], workout['activity_type'],
                             workout['start_unix'], workout['end_unix'], workout['duration_seconds'],
                             workout['energy_canonical'], workout['distance_canonical'],
                             workout['basal_energy_canonical'], workout['source_bundle'], workout['metadata'],
                             workout['raw'], int(deleted_before is not None), message['id']))
    if decoded is not None:
        held = sum(1 for change in decoded.get('changes', []))
        record('health_message_staged', state=state, error=error, duplicate=bool(exists),
               encrypted_bytes=len(payload), decrypted_bytes=len(plaintext) if plaintext is not None else None,
               message_id_type=decoded['message_id'], response=response,
               status_code=decoded.get('status', {}).get('code'),
               observed_samples=len(decoded['samples']), changes=held,
               observed_workouts=len(decoded['workouts']),
               deleted_samples=decoded.get('deleted_count', 0),
               native_progress_held=decoded.get('changes_present', False),
               progress_hold_reasons=sorted(held_reasons),
               data_applied=False, health_ack_sent=False)
        return {'decoded': decoded, 'pair_key': pair_key, 'digest': digest,
                'message_id': message['id'], 'correlated_to': message.get('peer') or None}
    record('health_message_staged', state=state, error=error, duplicate=bool(exists),
           encrypted_bytes=len(payload), decrypted_bytes=len(plaintext) if plaintext is not None else None,
           message_id_type=int.from_bytes(plaintext[:2], 'little') if plaintext and len(plaintext) >= 2 else None,
           response=response, status_code=decoded.get('status', {}).get('code') if decoded else None,
           observed_samples=len(decoded['samples']) if decoded else 0,
           data_applied=False, health_ack_sent=False)
    return {'decoded': None, 'pair_key': pair_key, 'digest': digest,
            'message_id': message['id'], 'correlated_to': message.get('peer') or None}
