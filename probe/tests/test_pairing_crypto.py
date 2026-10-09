"""Independent RFC 9383 and PIN vectors, plus authenticated framing."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pairing_crypto import SpakeProver, G, M, point_bytes, derive_pin
from ike_wire import Protected
from ike_keys import derive_sa_init_keys
from cryptography.exceptions import InvalidTag


def main():
    # RFC 9383 Appendix C.1; override only the random scalars/identities.
    p = SpakeProver(bytes(44), bytes(64), bytes(16))
    p.w0 = int('bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3', 16)
    p.w1 = int('7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba', 16)
    p.ephemeral = int('d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539', 16)
    p.share = point_bytes(G * p.ephemeral + M * p.w0)
    p.context = b'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors'
    p.idi, p.idr = b'client', b'server'
    assert p.share.hex() == '04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727'
    tag = p.accept_share(bytes.fromhex('04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048'))
    assert tag.hex() == '926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527'
    assert p.finish(bytes.fromhex('9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68')).hex() == '0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7'
    seed, ppk = derive_pin('012345', bytes(range(160, 192)), bytes.fromhex('208837d4ce64385000d01000'))
    assert seed[:32].hex() == 'b8d66ad794eb29d1b50c3e7f3fb7d3502a84a3644e30d47ecdb2119510929070'
    assert ppk.hex() == '6b5a77e96b100f1c14139afe4b9ccc8e60164d40220df33104879859cc828881aa342997cfba8a2affe94d701ac58529a225b2a5f1f75920382c71be4619d00f'
    keys = derive_sa_init_keys(bytes(56), bytes(32), bytes(32), b'i' * 8, b'r' * 8)
    sender, receiver = Protected(b'i' * 8, b'r' * 8, keys, False), Protected(b'i' * 8, b'r' * 8, keys)
    assert receiver.open(sender.seal(37, 0, 0, b'', response=True)[0], 37, 0) == (0, b'')
    plain = bytes(range(256)) * 7
    packets = sender.seal(43, 1, 34, plain, response=True)
    assert len(packets) == 2
    assert receiver.open(packets[1], 43, 1) is None
    assert receiver.open(packets[1], 43, 1) is None
    assert receiver.open(packets[0], 43, 1) == (34, plain)
    corrupted = bytearray(sender.seal(37, 2, 0, b'', response=True)[0])
    corrupted[-1] ^= 1
    try:
        receiver.open(bytes(corrupted), 37, 2)
        raise AssertionError('Accepted altered authenticated ciphertext')
    except InvalidTag:
        pass
    print('RFC SPAKE2+, Apple PIN/PPK, authenticated SK/SKF: OK')


if __name__ == '__main__':
    main()
