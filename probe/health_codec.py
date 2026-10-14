"""Bounded native SecMP v2 A-over-C protection for local Health messages.

23T240 profile: Class-A identities, RSA-1280 OAEP-SHA1, ECDSA-SHA1,
CTR embedded-key transform and CBC/PKCS7 payload in a binary plist.
"""
import hashlib
import hmac
import os
import plistlib

from Crypto.Util.asn1 import DerOctetString, DerSequence
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as rsa_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEALTH_TOPIC = 'com.apple.private.alloy.health.sync.classc'
MAX_PLAINTEXT = 512 * 1024
MAX_ENVELOPE = MAX_PLAINTEXT + 8192


def identity(encoded):
    if not isinstance(encoded, bytes) or not 80 <= len(encoded) <= 4096:
        raise ValueError('Invalid IDS identity size')
    sequence = DerSequence().decode(encoded, strict=True, nr_elements=2)
    parts = []
    for tag, value in zip((1, 2), sequence):
        part = DerOctetString(implicit=tag).decode(value, strict=True).payload
        if len(part) < 2 or int.from_bytes(part[:2], 'big') != len(part) - 2:
            raise ValueError('Invalid IDS identity component')
        parts.append(part)
    signing = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), parts[0][2:])
    encryption = serialization.load_der_public_key(parts[1][2:])
    if (not isinstance(encryption, rsa.RSAPublicKey) or encryption.key_size != 1280
            or encryption.public_numbers().e != 65537):
        raise ValueError('Unsupported IDS encryption identity')
    return signing, encryption, hashlib.sha256(b''.join(parts)).digest()


def transform(key, data, mode):
    operation = Cipher(algorithms.AES(key), mode).encryptor()
    return operation.update(data) + operation.finalize()


def oaep():
    return rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)


def protect(plaintext, signing_private, sender_public, recipient_public):
    if not isinstance(plaintext, bytes) or not 1 <= len(plaintext) <= MAX_PLAINTEXT:
        raise ValueError('Invalid Health plaintext size')
    signing, _, sender_hash = identity(sender_public)
    _, recipient, recipient_hash = identity(recipient_public)
    if (not isinstance(signing_private, ec.EllipticCurvePrivateKey)
            or not isinstance(signing_private.curve, ec.SECP256R1)
            or signing_private.public_key().public_numbers() != signing.public_numbers()):
        raise ValueError('Health signing identity mismatch')
    content_key = os.urandom(16)
    key_prefix = os.urandom(11)
    context = b'\x02' + sender_hash + recipient_hash
    tag = hmac.digest(key_prefix, content_key + context, 'sha256')[:5]
    transform_key = key_prefix + tag
    wrapped = transform(transform_key, content_key, modes.CTR(bytes(15) + b'\x01'))
    body = recipient.encrypt(transform_key + wrapped, oaep())
    signature = signing_private.sign(body, ec.ECDSA(hashes.SHA1()))
    if len(body) != 160 or not 8 <= len(signature) <= 80:
        raise ValueError('Unsupported Health capsule profile')
    capsule = b'\x02' + len(body).to_bytes(2, 'big') + body + bytes([len(signature)]) + signature
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encrypted = transform(content_key, padded, modes.CBC(bytes(16)))
    return plistlib.dumps({'ekd': capsule, 'sed': encrypted}, fmt=plistlib.FMT_BINARY, sort_keys=False)


def unprotect(encoded, encryption_private, sender_public, recipient_public):
    if (not isinstance(encoded, bytes) or not 1 <= len(encoded) <= MAX_ENVELOPE
            or not encoded.startswith(b'bplist00')):
        raise ValueError('Invalid Health envelope')
    envelope = plistlib.loads(encoded)
    if not isinstance(envelope, dict) or set(envelope) != {'ekd', 'sed'}:
        raise ValueError('Unsupported Health envelope fields')
    capsule, encrypted = envelope['ekd'], envelope['sed']
    if not isinstance(capsule, bytes) or not 172 <= len(capsule) <= 244:
        raise ValueError('Invalid Health capsule size')
    if capsule[0] != 2 or int.from_bytes(capsule[1:3], 'big') != 160:
        raise ValueError('Unsupported Health capsule version or key size')
    signature_size = capsule[163]
    if not 8 <= signature_size <= 80 or len(capsule) != 164 + signature_size:
        raise ValueError('Invalid Health signature size')
    if (not isinstance(encrypted, bytes) or not encrypted or len(encrypted) % 16
            or len(encrypted) > MAX_PLAINTEXT + 16):
        raise ValueError('Invalid Health ciphertext size')
    signing, _, sender_hash = identity(sender_public)
    _, recipient, recipient_hash = identity(recipient_public)
    if (not isinstance(encryption_private, rsa.RSAPrivateKey)
            or encryption_private.public_key().public_numbers() != recipient.public_numbers()):
        raise ValueError('Health encryption identity mismatch')
    body, signature = capsule[3:163], capsule[164:]
    signing.verify(signature, body, ec.ECDSA(hashes.SHA1()))
    embedded = encryption_private.decrypt(body, oaep())
    if len(embedded) != 32:
        raise ValueError('Unsupported Health embedded key size')
    transform_key = embedded[:16]
    content_key = transform(transform_key, embedded[16:], modes.CTR(bytes(15) + b'\x01'))
    context = b'\x02' + sender_hash + recipient_hash
    tag = hmac.digest(transform_key[:11], content_key + context, 'sha256')[:5]
    if not hmac.compare_digest(tag, transform_key[11:]):
        raise ValueError('Health identity integrity tag mismatch')
    decryptor = Cipher(algorithms.AES(content_key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    if not 1 <= len(plaintext) <= MAX_PLAINTEXT:
        raise ValueError('Invalid Health plaintext size')
    return plaintext
