"""Durable PoC identity. Private JSON and bond files stay in a 0700 directory.

The file is deliberately local and unencrypted; protect it like an SSH key.
No PIN, salt-derived password, ephemeral IKE key or Apple password is stored.
"""
import json
import os
from pathlib import Path
import secrets
import tempfile
import uuid
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from pairing_session import encode_tlvs, tlvs

PREFIX = bytes.fromhex('fd7465726d6e7573000d')


def user_owned(path):
    """Keep private research artifacts readable by the user invoking sudo."""
    if os.geteuid() == 0 and 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
        os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']), follow_symlinks=False)


def class_c(address):
    if len(address) != 16 or address[:10] != PREFIX:
        raise ValueError('Invalid NetworkRelay Class-D address')
    return address[:9] + b'\x0c' + address[10:]


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise ValueError('Pairing directory must be private (chmod 700) and not a symlink')
        user_owned(self.directory)
        self.path = self.directory / 'pairing.json'
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
                raise ValueError('Pairing file must be private (chmod 600) and not a symlink')
            self.data = json.loads(self.path.read_text())
            if self.data.get('format') != 1:
                raise ValueError('Unknown pairing-state format')
        else:
            address = bytearray(secrets.token_bytes(6))
            address[0] |= 0xc0
            self.data = {'format': 1, 'stage': 'created', 'host_address': address.hex(),
                         'ids_id': str(uuid.uuid4()), 'identity_uuid': uuid.uuid4().hex,
                         'identity_private': x25519.X25519PrivateKey.generate().private_bytes_raw().hex(),
                         'd_sign': ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex(),
                         'd_agree': x25519.X25519PrivateKey.generate().private_bytes_raw().hex(),
                         'c_sign': ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex(),
                         'c_agree': x25519.X25519PrivateKey.generate().private_bytes_raw().hex(),
                         'addresses': [(PREFIX + secrets.token_bytes(6)).hex() for _ in range(2)]}
            self.save()
        if 'host_irk' not in self.data:
            # A pre-existing bond used Bumble's default IRK; keep that identity.
            legacy = self.data.get('bonded') or (self.directory / 'bond.json').exists()
            self.save(host_irk=(bytes(16) if legacy else secrets.token_bytes(16)).hex())
        if len(self.key('host_irk')) != 16:
            raise ValueError('Companion Bluetooth IRK must contain sixteen bytes')

    def key(self, name):
        return bytes.fromhex(self.data[name])

    def sign(self, lane):
        return ed25519.Ed25519PrivateKey.from_private_bytes(self.key(lane + '_sign'))

    def identity(self):
        return x25519.X25519PrivateKey.from_private_bytes(self.key('identity_private'))

    def save(self, **updates):
        self.data.update(updates)
        fd, name = tempfile.mkstemp(prefix='.pairing-', dir=self.directory)
        try:
            with os.fdopen(fd, 'w') as output:
                json.dump(self.data, output, indent=2)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.path)
            user_owned(self.path)
            directory = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def local_notifies(self, oob, name, build):
        i, r = [bytes.fromhex(address) for address in self.data['addresses']]
        batch = {0xc547: b'r' + oob.r + b'c' + oob.c}
        for tag, lane in ((0xc548, 'd'), (0xc549, 'c')):
            agreement = x25519.X25519PrivateKey.from_private_bytes(self.key(lane + '_agree'))
            batch[tag] = encode_tlvs({1: self.sign(lane).public_key().public_bytes_raw(),
                                     2: agreement.public_key().public_bytes_raw()})
        batch.update({0xc4af: self.key('identity_uuid') + self.identity().public_key().public_bytes_raw(),
                      0xbdda: b'\0\x18', 0xbddb: name.encode(), 0xbddc: build.encode(),
                      0xbdde: b'\x01', 0xc8c9: b'\x01', 0xbddf: self.data['ids_id'].encode(),
                      0xc671: i, 0xc672: r, 0xc67b: class_c(i), 0xc67c: class_c(r)})
        if any(len(batch[tag]) not in range(1, 255) for tag in (0xbddb, 0xbddc, 0xbddf)):
            raise ValueError('Companion metadata must be 1..254 UTF-8 bytes')
        return batch

    def enroll_peer(self, batch):
        # Only require credentials consumed by SMP and ordinary IKE. Other
        # notifies are opaque metadata, not mandatory echoes of our request.
        for tag in (0xc547, 0xc548, 0xc549, 0xc4af):
            if tag not in batch:
                raise ValueError(f'Missing peer enrollment notify 0x{tag:04x}')
        for tag, size in ((0xc547, 34), (0xc4af, 48)):
            if len(batch[tag]) != size:
                raise ValueError(f'Invalid peer enrollment notify 0x{tag:04x}: expected {size} bytes, got {len(batch[tag])}')
        if batch[0xc547][0] != ord('r') or batch[0xc547][17] != ord('c'):
            raise ValueError('Invalid Watch Bluetooth OOB encoding')
        for tag in (0xc548, 0xc549):
            keys = tlvs(batch[tag])
            if any(len(keys.get(kind, b'')) != 32 for kind in (1, 2)):
                raise ValueError('Invalid peer public-key enrollment')
            ed25519.Ed25519PublicKey.from_public_bytes(keys[1])
            x25519.X25519PublicKey.from_public_bytes(keys[2])
        # Ordinary IKE authenticates operational addresses in its CFG_REPLY.
        self.save(peer_notifies={str(tag): value.hex() for tag, value in batch.items()},
                  stage='keys_enrolled')

    def peer_notifies(self):
        return {int(tag): bytes.fromhex(value) for tag, value in self.data['peer_notifies'].items()}

    def peer_keys(self, lane):
        return tlvs(self.peer_notifies()[0xc548 if lane == 'd' else 0xc549])
