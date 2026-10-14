"""Bounded v17 Health frame decoder. Decoding never implies native sync progress."""
import math
import uuid

from apple_codec import one, protobuf
from health_codec import MAX_PLAINTEXT


MESSAGE_IDS = frozenset((1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14))
APPLE_EPOCH = 978307200


def child(fields, number):
    data = one(fields, number)
    if not isinstance(data, bytes):
        raise ValueError('Missing Health protobuf child')
    return protobuf(data)


def pairing_uuid(data):
    if not isinstance(data, bytes) or len(data) != 16:
        raise ValueError('Invalid Health UUID')
    return str(uuid.UUID(bytes=data))


def finite(value):
    if type(value) not in (float, int) or not math.isfinite(value):
        raise ValueError('Invalid Health quantity or date')
    return float(value)


def entity_code(change):
    # The native v17 writer includes the legacy object type (field 1); field 9
    # identifies its schema/entity and is especially useful for dependencies.
    legacy = {10: 11, 12: 13, 1: 2, 2: 4, 16: 16, 17: 17}.get(one(change, 1))
    if legacy is not None:
        return legacy
    modern = one(change, 9)
    if modern is not None:
        if not isinstance(modern, bytes):
            raise ValueError('Invalid Health entity identifier')
        identifier = protobuf(modern)
        value = one(identifier, 2)
        return value if type(value) is int else None
    return None


def entity_identity(fields, number, code):
    raw = one(fields, number)
    identity = protobuf(raw) if isinstance(raw, bytes) else {}
    schema = one(identity, 1, b'')
    if not isinstance(schema, bytes) or len(schema) > 1024:
        raise ValueError('Invalid Health entity schema')
    schema = schema.decode('utf-8')
    if raw is not None and (not isinstance(raw, bytes) or one(identity, 2) != code):
        raise ValueError('Inconsistent Health entity identity')
    return {'entity': code, 'schema': schema, 'identity_raw': raw}


def decode_anchor(encoded):
    if not isinstance(encoded, bytes):
        raise ValueError('Invalid Health anchor')
    anchor = protobuf(encoded)
    code = entity_code({9: anchor[3]}) if 3 in anchor else entity_code({1: [one(anchor, 1)]})
    value = one(anchor, 2)
    if type(value) is not int or not 0 <= value < 1 << 63:
        raise ValueError('Invalid Health anchor value')
    return {**entity_identity(anchor, 3, code), 'anchor': value}


def decode_sample(encoded, *, quantity):
    sample = protobuf(encoded)
    header = child(sample, 1)
    object_bytes = one(header, 1)
    health_object = protobuf(object_bytes) if isinstance(object_bytes, bytes) else {}
    sample_uuid = pairing_uuid(one(health_object, 1))
    start, end = finite(one(header, 3)), finite(one(header, 4))
    if end < start:
        raise ValueError('Invalid Health sample date range')
    data_type = one(header, 2)
    source_bundle = one(health_object, 3)
    if source_bundle is not None:
        if not isinstance(source_bundle, bytes) or len(source_bundle) > 1024:
            raise ValueError('Invalid Health source bundle')
        source_bundle = source_bundle.decode('utf-8')
    result = {'uuid': sample_uuid, 'data_type': data_type,
              'start_unix': start + APPLE_EPOCH, 'end_unix': end + APPLE_EPOCH,
              'source_bundle': source_bundle,
              'created_unix': (finite(one(health_object, 4)) + APPLE_EPOCH
                               if one(health_object, 4) is not None else None),
              'external_sync_code': one(health_object, 5),
              'metadata': one(health_object, 2), 'raw': encoded}
    if quantity:
        canonical, original, unit = one(sample, 2), one(sample, 3), one(sample, 4)
        canonical = finite(canonical) if canonical is not None else None
        original = finite(original) if original is not None else None
        if unit is not None:
            if not isinstance(unit, bytes) or len(unit) > 256:
                raise ValueError('Invalid Health unit')
            unit = unit.decode('utf-8')
        result.update(canonical=canonical, original=original, original_unit=unit)
        if data_type == 5:
            bpm = original if unit == 'count/min' else None
            if bpm is None and canonical is not None and unit in (None, 'count/s'):
                bpm = finite(canonical * 60)
            result['bpm'] = bpm
    return result


def decode_workout(encoded):
    """23T240 HDCodableWorkout summary; nested events/activities remain in raw."""
    fields = protobuf(encoded)
    result = decode_sample(encoded, quantity=False)
    activity = one(fields, 2)
    if activity is not None and (type(activity) is not int or not 0 <= activity < 1 << 63):
        raise ValueError('Invalid workout activity type')
    result['activity_type'] = activity
    for number, name in ((4, 'duration_seconds'), (5, 'energy_canonical'),
                         (6, 'distance_canonical'), (9, 'basal_energy_canonical')):
        value = one(fields, number)
        value = finite(value) if value is not None else None
        if value is not None and value < 0:
            raise ValueError('Invalid negative workout summary value')
        result[name] = value
    return result


def decode_change(encoded):
    change = protobuf(encoded)
    code = entity_code(change)
    identity = entity_identity(change, 9, code)
    start, end, sequence = one(change, 2), one(change, 3), one(change, 7)
    # 23T240 writer/reader and setters: field 6 speculative, field 8 complete.
    # The reference receive policy reverses these two fields.
    complete = one(change, 8)
    if any(value is not None and (type(value) is not int or not 0 <= value < 1 << 63)
           for value in (start, end, sequence)):
        raise ValueError('Invalid Health range or sequence')
    if complete is not None and (type(complete) is not int or complete not in (0, 1)):
        raise ValueError('Invalid Health completion flag')
    speculative = one(change, 6, 0)
    if type(speculative) is not int or speculative not in (0, 1):
        raise ValueError('Invalid Health speculative flag')
    dependencies = []
    for item in change.get(5, []):
        if not isinstance(item, bytes):
            raise ValueError('Invalid Health dependency anchor')
        dependencies.append(decode_anchor(item))
    objects, samples, workouts, deleted = [], [], [], []
    for item in change.get(4, []):
        if not isinstance(item, bytes):
            raise ValueError('Invalid Health object data')
        objects.append(item)
        if code in (2, 4, 5) and not identity['schema']:
            collection = protobuf(item)
            field = {2: 3, 4: 4, 5: 5}[code]
            for encoded_sample in collection.get(field, []):
                if not isinstance(encoded_sample, bytes):
                    raise ValueError('Invalid Health sample object')
                if code == 5:
                    workouts.append(decode_workout(encoded_sample))
                    if len(workouts) > 512:
                        raise ValueError('Too many workout summaries')
                else:
                    samples.append(decode_sample(encoded_sample, quantity=code == 4))
            for tombstone in collection.get(9, []):
                if not isinstance(tombstone, bytes):
                    raise ValueError('Invalid Health deletion record')
                deleted_sample = one(protobuf(tombstone), 1)
                deleted.append(decode_sample_from_header(deleted_sample, tombstone))
    # Bound each change, not the sum of independent changes in one frame.
    # A Watch frame can legitimately carry several thousand-record collections.
    if len(samples) + len(workouts) > 4096 or len(deleted) > 4096:
        raise ValueError('Too many Health records in one change')
    return {**identity, 'start': start, 'end': end, 'sequence': sequence,
            'complete': complete, 'speculative': speculative == 1,
            'dependencies': dependencies, 'objects': objects,
            'samples': samples, 'workouts': workouts, 'deleted': deleted, 'raw': encoded}


def decode_sample_from_header(encoded, tombstone):
    if not isinstance(encoded, bytes):
        raise ValueError('Invalid Health deletion sample header')
    if not isinstance(tombstone, bytes):
        raise ValueError('Invalid Health deletion record')
    header = protobuf(encoded)
    object_bytes = one(header, 1)
    health_object = protobuf(object_bytes) if isinstance(object_bytes, bytes) else {}
    start, end = finite(one(header, 3)), finite(one(header, 4))
    if end < start:
        raise ValueError('Invalid Health deletion date range')
    return {'uuid': pairing_uuid(one(health_object, 1)), 'data_type': one(header, 2),
            'start_unix': start + APPLE_EPOCH, 'end_unix': end + APPLE_EPOCH,
            'raw': tombstone}


def decode_health_frame(data, *, response=False):
    header = 2 if response else 3
    if not isinstance(data, bytes) or not header <= len(data) <= MAX_PLAINTEXT:
        raise ValueError('Invalid Health frame size')
    message_id = int.from_bytes(data[:2], 'little')
    if message_id not in MESSAGE_IDS:
        raise ValueError('Unsupported Health message ID')
    result = {'message_id': message_id, 'priority': None if response else data[2],
              'response': response, 'samples': [], 'change_count': 0, 'deleted_count': 0,
              'changes': [], 'workouts': []}
    if message_id not in (1, 2, 7):
        return result
    envelope = protobuf(data[header:])
    version = one(envelope, 2)
    if type(version) is not int or version != 17:
        raise ValueError('Unsupported Health sync version')
    result.update(version=version, persistent=pairing_uuid(one(envelope, 3)),
                  health=pairing_uuid(one(envelope, 4)))
    encoded_restore = one(envelope, 9)
    if encoded_restore is not None:
        if not isinstance(encoded_restore, bytes):
            raise ValueError('Invalid Health Restore record')
        restore = protobuf(encoded_restore)
        restore_id = pairing_uuid(one(restore, 1))
        sequence, status = one(restore, 2), one(restore, 3)
        source = one(restore, 4)
        if sequence is None or status is None or (source is not None and not isinstance(source, bytes)):
            raise ValueError('Invalid Health Restore fields')
        result['restore'] = {'session': restore_id, 'sequence': sequence, 'status': status,
                             'source': source.decode('utf-8') if source is not None else None}
    encoded_status = one(envelope, 8)
    if encoded_status is not None:
        if not isinstance(encoded_status, bytes):
            raise ValueError('Invalid Health status record')
        status = protobuf(encoded_status)
        if len(status.get(2, [])) > 512:
            raise ValueError('Too many Health status anchors')
        result['status'] = {'code': one(status, 1), 'anchor_count': len(status.get(2, [])),
                            'anchors': [decode_anchor(item) for item in status.get(2, [])]}
    encoded_changes = one(envelope, 7)
    result['changes_present'] = encoded_changes is not None
    if encoded_changes is not None:
        if not isinstance(encoded_changes, bytes):
            raise ValueError('Invalid Health change set')
        change_set = protobuf(encoded_changes)
        changes = change_set.get(1, [])
        session = one(change_set, 2)
        result['change_set'] = {'session': pairing_uuid(session) if session is not None else None,
                                'start_date': finite(one(change_set, 3)) if 3 in change_set else None,
                                'status': one(change_set, 5), 'error_raw': one(change_set, 4)}
        if 4 in change_set:
            error = child(change_set, 4)
            result['change_set']['error'] = {'domain': one(error, 1, b'').decode('utf-8'),
                                            'code': one(error, 2)}
        if len(changes) > 512:
            raise ValueError('Too many Health changes')
        if any(not isinstance(item, bytes) for item in changes):
            raise ValueError('Invalid Health change')
        result['changes'] = [decode_change(item) for item in changes]
        result['change_count'] = len(changes)
        workout_count = sum(len(change['workouts']) for change in result['changes'])
        if workout_count > 512:
            raise ValueError('Too many workout summaries')
        for change in result['changes']:
            for sample in change['samples']:
                if sample.get('data_type') == 5 and sample.get('bpm') is not None:
                    result['samples'].append(sample)
            result['workouts'].extend(change['workouts'])
            result['deleted_count'] += len(change['deleted'])
    return result
