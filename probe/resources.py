"""Durable native IDS resource chunks; acknowledge only after verified storage."""
import os
import plistlib
import uuid
from ids_wire import decompress


def save_resource(store, identifier, payload):
    identifier = str(uuid.UUID(identifier))
    directory = store.directory / 'resources'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError('Resource directory must be private and not a symlink')
    legacy = payload[:3] == b'\x01\x1f\x8b'
    if legacy:
        payload = decompress(payload[1:])
    initial = payload.startswith(b'bplist00')
    records = store.data.get('ids_resources', {}).copy()
    metadata = records.get(identifier)
    if initial:
        header = plistlib.loads(payload)
        prefix = 'ids-message-resource-transfer-'
        total, url, payload = (header[prefix + key] for key in ('total-bytes', 'url', 'data'))
        if type(total) is not int or not 0 <= total <= 512 * 1024 * 1024 or not isinstance(url, str) or not isinstance(payload, bytes):
            raise ValueError('Invalid IDS resource header')
        incoming = {'total': total, 'url': url, 'legacy': legacy}
        if metadata is not None and metadata != incoming:
            raise ValueError('Resource header changed during retry')
        metadata = incoming
    if metadata is None:
        raise ValueError('Resource continuation arrived without its header')
    if metadata['legacy'] and initial:
        offset = 0
    else:
        if len(payload) < 8:
            raise ValueError('Resource offset is missing')
        offset, payload = int.from_bytes(payload[:8], 'big'), payload[8:]
    if offset + len(payload) > metadata['total']:
        raise ValueError('Resource chunk exceeds declared size')
    if identifier not in records:
        if offset or len(records) >= 64:
            raise ValueError('Invalid initial resource offset or too many resource files')
        records[identifier] = metadata
        store.save(ids_resources=records)
    partial, complete = directory / (identifier + '.partial'), directory / (identifier + '.bin')
    target = complete if complete.exists() else partial
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(target, flags, 0o600), 'r+b') as output:
        output.seek(0, os.SEEK_END)
        received = output.tell()
        if offset > received or offset < received and offset + len(payload) > received:
            raise ValueError('Resource chunk leaves a gap or overlaps partially')
        output.seek(offset)
        if offset < received:
            if output.read(len(payload)) != payload:
                raise ValueError('Repeated resource chunk changed')
        else:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            received += len(payload)
    if received == metadata['total'] and target == partial:
        os.replace(partial, complete)
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return received, metadata['total']
