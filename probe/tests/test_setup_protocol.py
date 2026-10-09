"""Portable checks for setup gates, wire admission, resources and activation."""
import asyncio
import gzip
import ipaddress
import plistlib
from pathlib import Path
import struct
import sys
import tempfile
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from activation import ActivationProxy
from apple_codec import (ARCHIVE_KEY, Archive, CREDS, NANO_C, PBB, PSY, bplist,
    field, nr_properties, one, preferences, protobuf, sync_state)
from ids_wire import application, nwsc_accept, nwsc_start, parse_application, parse_hello, hello
from ike_keys import derive_sa_init_keys
from normal_crypto import CHILD_SELECT, ED_AUTH, TS, Esp, OrdinarySession, open_identifier, seal_identifier
from normal_link import accept_prelude, prelude
from nrlp import Stream, build_inner_message
from pairing_store import Store, class_c
from ike_wire import chain, notify, payloads, unique
from resources import save_resource
from setup_flow import SetupFlow, local_identities
from watch_link import Ertm


def rejects(action, errors=(ValueError, InvalidSignature, InvalidTag)):
    try:
        action()
    except errors:
        return
    raise AssertionError('Invalid input was accepted')


def activation_archive(url='https://albert.apple.com/deviceActivation'):
    # A native NSURLRequest object table, independent of our archive encoder.
    objects = ['$null', {'$classname': 'NSMutableURLRequest'}, {'$classname': 'NSURL'},
               {'$classname': 'NSDictionary'}, url, 30.0, 'POST',
               'X-iOS-Activation-Medium', 'Bluetooth', b'<signed-request> unchanged </signed-request>']
    objects += [{'NS.relative': plistlib.UID(4), 'NS.base': plistlib.UID(0), '$class': plistlib.UID(2)},
                {'NS.keys': [plistlib.UID(7)], 'NS.objects': [plistlib.UID(8)], '$class': plistlib.UID(3)}]
    objects.append({'$class': plistlib.UID(1), '$0': 1, '$1': 7, '$2': 21,
        **{'__nsurlrequest_proto_prop_obj_' + str(key): plistlib.UID(value)
           for key, value in {1: 10, 2: 5, 18: 6, 19: 11, 20: 9}.items()}})
    return bplist({'$archiver': 'NSKeyedArchiver', '$version': 100000,
                   '$objects': objects, '$top': {ARCHIVE_KEY: plistlib.UID(12)}})


def wire_checks(store):
    assert parse_hello(hello(store.data['ids_id'], uuid.uuid4())[2:])['device'] == uuid.UUID(store.data['ids_id'])
    private = ed25519.Ed25519PrivateKey.generate()
    packet = nwsc_start(12345, 987, 'ids-control-channel', private)
    assert nwsc_accept(packet, private.public_key().public_bytes_raw()) == ('ids-control-channel', 987)
    bad = bytearray(packet)
    bad[-1] ^= 1
    rejects(lambda: nwsc_accept(bytes(bad), private.public_key().public_bytes_raw()))
    identifier = str(uuid.uuid4())
    encoded = application(3, 4, PBB, identifier, field(1, 10), 3, flags=1)
    decoded = parse_application(encoded[0], encoded[5:], {})
    assert decoded['id'] == identifier and decoded['payload'] == field(1, 10) and decoded['type'] == 3
    for kind in (2, 3, 4, 100, 101, 104, 105):
        stream, wire = Stream(), build_inner_message(b'payload', kind)
        assert stream.feed(wire[:4]) == []
        assert stream.feed(wire[4:]) == [(kind, b'payload')]
        bad = bytearray(wire)
        bad[-1] ^= 1
        rejects(lambda: Stream().feed(bytes(bad)))
    peer = prelude(uuid.uuid4().bytes)
    assert accept_prelude(peer, prelude()) == peer[15:31]
    rejects(lambda: accept_prelude(prelude(), peer))

    identity = x25519.X25519PrivateKey.generate()
    label, nonces, spis = b'classD', bytes(range(64)), bytes(range(16))
    encoded = seal_identifier(identity.public_key().public_bytes_raw(), bytes(16), label, nonces, spis)
    open_identifier(identity, bytes(16), label, nonces, spis, encoded)
    rejects(lambda: open_identifier(identity, bytes(16), b'classC', nonces, spis, encoded))
    rejects(lambda: open_identifier(identity, bytes([1]) * 16, label, nonces, spis, encoded))

    keys = derive_sa_init_keys(bytes(56), bytes(32), bytes(32), bytes(8), b'R' * 8)
    sender, receiver = Esp(keys, bytes(32), bytes(32), b'iiii', b'rrrr'), Esp(keys, bytes(32), bytes(32), b'rrrr', b'iiii')
    receiver.rx_key = sender.tx_key
    addresses = ipaddress.IPv6Address('fd00::1').packed + ipaddress.IPv6Address('fd00::2').packed
    clear = struct.pack('>IHBB', 0x60000000, 5, 6, 64) + addresses + b'hello'
    encrypted = sender.seal(clear)
    bad = bytearray(encrypted)
    bad[-1] ^= 1
    rejects(lambda: receiver.open(bytes(bad)))
    assert receiver.open(encrypted) == clear and receiver.open(encrypted) is None
    sender.sequence[0] = (1 << 30) - 2
    assert receiver.open(sender.seal(clear)) == clear  # a large valid jump keeps a bounded replay bitmap
    assert receiver.seen[0] == 1


def activation_checks():
    seen = []
    body = b'<?xml version="1.0"?>\n<plist>\n signed bytes \n</plist>\n'
    def server(request):
        seen.append(request)
        assert request.content == b'<signed-request> unchanged </signed-request>'
        assert request.headers['X-iOS-Activation-Medium'] == 'WiFi'
        if len(seen) == 1:
            return httpx.Response(307, headers={'Location': 'https://albert.apple.com/final'})
        return httpx.Response(200, content=body, headers={'ARS': 'signature-exact'})
    proxy = ActivationProxy(lambda *a, **k: None)
    hooks = proxy.client.event_hooks
    proxy.close()
    proxy.client = httpx.Client(transport=httpx.MockTransport(server), follow_redirects=True, event_hooks=hooks)
    try:
        result = protobuf(proxy.exchange(activation_archive()))
        assert len(seen) == 2 and one(result, 1) == body
        archived = Archive(one(result, 2), ARCHIVE_KEY)
        assert archived.decode(archived.root)['ARS'] == 'signature-exact'
        rejects(lambda: proxy.exchange(activation_archive('https://example.com/activation')))
    finally:
        proxy.close()
    proxy = ActivationProxy(lambda *a, **k: None)
    hooks = proxy.client.event_hooks
    proxy.close()
    seen.clear()
    def redirect_outside(request):
        seen.append(request)
        return httpx.Response(307, headers={'Location': 'https://example.com/activation'})
    proxy.client = httpx.Client(transport=httpx.MockTransport(redirect_outside), follow_redirects=True, event_hooks=hooks)
    try:
        rejects(lambda: proxy.exchange(activation_archive()))
        assert len(seen) == 1  # no activation body is sent to the rejected endpoint
    finally:
        proxy.close()


def resource_checks(store):
    identifier = str(uuid.uuid4())
    prefix = 'ids-message-resource-transfer-'
    header = bplist({prefix + 'total-bytes': 6, prefix + 'url': 'file:///some/watch-file', prefix + 'data': bytes(8) + b'abc'})
    assert save_resource(store, identifier, header) == (3, 6)
    assert save_resource(store, identifier, header) == (3, 6)
    rejects(lambda: save_resource(store, identifier, (5).to_bytes(8, 'big') + b'x'))
    assert save_resource(store, identifier, (3).to_bytes(8, 'big') + b'def') == (6, 6)
    rejects(lambda: save_resource(store, identifier, (3).to_bytes(8, 'big') + b'BAD'))
    assert (store.directory / 'resources' / (identifier + '.bin')).read_bytes() == b'abcdef'
    legacy_id = str(uuid.uuid4())
    legacy = bplist({prefix + 'total-bytes': 3, prefix + 'url': 'file:///old', prefix + 'data': b'old'})
    assert save_resource(store, legacy_id, b'\x01' + gzip.compress(legacy)) == (3, 3)


class FakeIds:
    def __init__(self, peer):
        self.peer_hello = {'maximum': 26, 'device': uuid.UUID(peer.data['ids_id'])}
        self.sent, self.queue = [], asyncio.Queue()

    async def send(self, topic, kind, payload=b'', **kwargs):
        result = {'sequence': len(self.sent), 'id': str(uuid.uuid4()).upper(), 'topic': topic}
        self.sent.append({**result, 'type': kind, 'payload': payload, **kwargs})
        return result

    async def receive(self):
        return await self.queue.get()

    async def wait_transport_quiet(self, minimum_wait=0):
        pass  # Offline transport has no queued bytes.


async def setup_checks(store, peer, early_sync=False):
    ids = FakeIds(peer)
    flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
    task = asyncio.create_task(flow.run())
    async def push(topic=None, kind=None, payload=b'', **fields):
        if topic:
            event = {'event': 'message', 'topic': topic, 'type': kind, 'payload': payload,
                     'id': str(uuid.uuid4()), 'peer': '', 'response': False, 'flags': 0, **fields}
        else:
            event = fields
        await ids.queue.put(event)
        for _ in range(10):
            await asyncio.sleep(0)
        if task.done():
            task.result()
    try:
        peer_public = local_identities(peer)
        await push(CREDS, payload=bplist({'command': 11, 'unique-id': str(uuid.uuid4())}))
        await push(CREDS, payload=bplist({'command': 12, 'unique-id': flow.request_id, 'success': True,
            'identifier': peer.data['ids_id'], 'encryption-key': peer_public['D'],
            'encryption-class-a-key': peer_public['A'], 'encryption-class-c-key': peer_public['C']}))
        assert flow.check is None
        await push(event='ack', sequence=next(iter(flow.local_info_sequences)), lane='d')
        await push(event='ack', sequence=flow.check['sequence'], lane='d')
        await push(event='ack', sequence=flow.snapshot['sequence'], lane='c')
        await push(NANO_C, 4, nr_properties({'productType': 'Watch7,14', 'modelNumber': 'test',
            'chipID': 1, 'capabilities': [uuid.uuid4()], 'isSetup': False}, response=True), response=True)
        assert flow.configured and not task.done()
        await push(PBB, 20, field(1, 1.0))
        assert flow.prepare is None  # locale completion alone cannot imply activation
        await push(PBB, 4)
        assert flow.prepare is not None
        await push(PBB, 18, peer=str(uuid.uuid4()))
        assert flow.completion is None  # an unrelated PrepareInitialSync reply cannot unlock completion
        if early_sync:
            await push(PSY, 0, sync_state(True))
            assert not flow.sync_complete
        await push(PBB, 18, peer=flow.prepare['id'])
        assert flow.completion is not None and not task.done()
        if not early_sync:
            await push(PSY, 0, preferences('com.apple.pairedsync', {'PSYWatchSyncState':
                {'version': 1, 'syncProgressState': 3, 'globalProgress': 100}}))
            assert not flow.sync_complete
            # Backup field 1 is a container string, not a timestamp.
            backup = field(1, 'container') + field(2, 'com.apple.pairedsync') + field(3,
                field(1, 'PSYWatchSyncClientState') + field(2, bplist({'version': 1, 'syncProgressState': 3})))
            await push(PSY, 2, backup)
        assert flow.sync_complete and not task.done()
        await push(NANO_C, 2, nr_properties({'isSetup': True}))
        await push(event='app_ack', topic=PSY, peer=str(uuid.uuid4()), lane='c')
        assert not task.done()
        if early_sync:
            await push(NANO_C, 2, nr_properties({'isSetup': False}))
        await push(event='app_ack', topic=PSY, peer=flow.completion['id'], lane='c')
        if early_sync:
            assert not task.done()  # A current false registry state blocks completion.
            await push(NANO_C, 2, nr_properties({'isSetup': True}))
        await asyncio.wait_for(task, 1)
        assert store.data['stage'] == 'setup_protocol_complete' and store.data['setup_complete']
        reconnect = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
        before = len(ids.sent)
        reconnect.peer_info = reconnect.local_info_ack = True
        await reconnect.advance()
        assert reconnect.property_request is not None
        assert all(m['topic'] == NANO_C and m['type'] == 4 for m in ids.sent[before:])
        assert reconnect.check is None and reconnect.normal is None and reconnect.prepare is None
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def ertm_checks():
    class Connection:
        def send_l2cap_pdu(self, cid, packet):
            controls = struct.unpack_from('<H', packet)[0]
            if controls & 1:
                return
            self.peer.feed(packet)
    first, second = Connection(), Connection()
    a, b = Ertm(first, 70, lambda *a, **k: None, 3), Ertm(second, 99, lambda *a, **k: None, 3)
    first.peer, second.peer = b, a
    # Supervisory feedback is routed too; deliberately drop the first ACK.
    dropped = False
    def send_b(cid, packet):
        nonlocal dropped
        if packet[0] & 1 and not dropped:
            dropped = True
            return
        a.feed(packet)
    second.send_l2cap_pdu = send_b
    for n in range(66):
        await a.send(bytes([n]))
        assert await asyncio.wait_for(b.receive(), 1) == bytes([n])
    assert b.incoming.empty() and a.tx_seq == b.rx_seq == 2
    b.feed(struct.pack('<H', 0x4000))
    assert isinstance(b.error, ValueError)


async def ordinary_checks(store, peer):
    from types import SimpleNamespace
    oob = SimpleNamespace(r=bytes(16), c=b'C' * 16)
    store.enroll_peer(peer.local_notifies(oob, 'Watch', '23T240'))
    for lane in ('d', 'c'):
        local, remote = prelude(), prelude(uuid.uuid4().bytes)
        session = OrdinarySession(None, lambda *a, **k: None, store, lane, local, remote)
        session.spi_r, session.peer_nonce = b'RESPONDR', b'N' * 32
        session.peer_wire = b'synthetic responder SA_INIT'
        session.int_i, session.int_r = b'I' * 64, b'R' * 64
        session.keys = derive_sa_init_keys(bytes(56), session.initial.nonce, session.peer_nonce,
                                          session.initial.initiator_spi, session.spi_r)
        local_d, peer_d = [bytes.fromhex(value) for value in store.data['addresses']]
        local_ip, remote_ip = (local_d, peer_d) if lane == 'd' else (class_c(local_d), class_c(peer_d))
        messages = []
        response_id, bad_signature = None, False
        async def exchange(ex, mid, first, plain):
            messages.append(mid)
            if ex == 37:
                assert mid in (3, 4) and first == 41
                return 0, b''
            assert ex == 35 and mid == 2 and len(plain) == 543
            request = payloads(first, plain)
            idi, auth = unique(request, 35), unique(request, 39)
            open_identifier(peer.identity(), peer.key('identity_uuid'), session.service,
                            session.initial.nonce + session.peer_nonce, session.initial.initiator_spi + session.spi_r, idi)
            assert len(auth) == 76 and auth[:12] == ED_AUTH
            store.sign(lane).public_key().verify(auth[12:], session.signed_octets(idi))
            # The ordinary IKE responder uses a plain service
            # KEY_ID, unlike the HPKE-encrypted initiator ID validated above.
            idr = b'\x0b\0\0\0' + session.service if response_id is None else response_id
            auth = ED_AUTH + peer.sign(lane).sign(session.signed_octets(idr, True))
            if bad_signature:
                auth = auth[:-1] + bytes([auth[-1] ^ 1])
            sa = bytes.fromhex('0000002001030402') + b'SPIr' + CHILD_SELECT
            cfg = b'\x02\0\0\0\x65\x66\0\x10' + local_ip + b'\x65\x67\0\x10' + remote_ip
            reply = [(36, idr), (39, auth), (33, sa), (47, cfg), (44, TS), (45, TS)]
            reply += [(41, notify(code)) for code in (0x4007, 0x400a, 0x400b, 0xc350)]
            reply += [(41, notify(0xbe3d, b'\x80')), (41, notify(0xbdd9, remote))]
            return 36, chain(reply)
        session.exchange = exchange
        await session.authenticate()
        assert messages == ([2, 3, 4] if lane == 'd' else [2])
        assert session.local_address == local_ip and session.remote_address == remote_ip
        assert session.remote_unlocked.is_set()
        # Wrong services are rejected even with a valid peer signature. The
        # correct service still requires AUTH from the enrolled Ed25519 key.
        encrypted = seal_identifier(store.identity().public_key().public_bytes_raw(),
                                    store.key('identity_uuid'), session.service,
                                    session.initial.nonce + session.peer_nonce,
                                    session.initial.initiator_spi + session.spi_r)
        for response_id in (b'\x0b\0\0\0wrong-service', b'\x0d\0\0\0' + session.service,
                            b'\x0b\x01\0\0' + session.service, encrypted):
            try:
                await session.authenticate()
            except ValueError as error:
                assert 'requested service' in str(error)
            else:
                raise AssertionError('Invalid responder service identifier accepted')
        response_id, bad_signature = None, True
        try:
            await session.authenticate()
        except InvalidSignature:
            pass
        else:
            raise AssertionError('Invalid responder AUTH accepted')


def main():
    with tempfile.TemporaryDirectory() as directory:
        store, peer = Store(Path(directory) / 'host'), Store(Path(directory) / 'watch')
        wire_checks(store)
        activation_checks()
        resource_checks(store)
        asyncio.run(setup_checks(store, peer))
        asyncio.run(ertm_checks())
        asyncio.run(ordinary_checks(store, peer))
    print('NWSC, HPKE/ESP, NRLP, activation bytes/redirects, resources, setup receipts, ERTM retries: OK')


if __name__ == '__main__':
    main()
