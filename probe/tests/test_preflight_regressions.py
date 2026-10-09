"""Offline regressions for bond ordering, IDS startup, setup gates and TUN errors."""
import asyncio
import ipaddress
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, PropertyMock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric import ed25519
from apple_codec import CREDS, NANO_C, NANO_D, PBB, PSY, bplist, nr_properties, sync_state, field
from ids_session import IdsSession
from ids_wire import (nwsc_start, nwsc_probe, nwsc_feedback, parse_nwsc_feedback,
                      nwsc_accept, parse_setup, frame, hello, control_frame, application, parse_application, Cursor)
from normal_link import NormalLink, Tun, decode_lowpan, prelude, accept_prelude
from normal_crypto import Esp
from pairing_store import Store, PREFIX, class_c, user_owned
from pairing_session import IkeSession, encode_tlvs, tlvs
from ike_keys import derive_sa_init_keys
from ike_wire import Protected, chain, notify
from setup_flow import SetupFlow
from test_setup_protocol import FakeIds, setup_checks
from watch_poc import finish_bond, run
from watch_link import RelayLink
from nrlp import build_inner_message, Stream


class Connection:
    def __init__(self, blocked=False):
        self.listeners = {}
        self.started = asyncio.Event()
        self.blocked = blocked
        self.cancelled = False

    def on(self, event, callback):
        self.listeners[event] = callback

    def remove_listener(self, event, callback):
        assert self.listeners[event] is callback
        del self.listeners[event]

    def emit(self, event, *args):
        self.listeners[event](*args)

    async def pair(self):
        self.started.set()
        try:
            if self.blocked:
                await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class Writer:
    def __init__(self, blocked=False):
        self.written = []
        self.draining = asyncio.Event()
        self.release = asyncio.Event()
        if not blocked:
            self.release.set()
        self.closed = False

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        self.draining.set()
        await self.release.wait()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def ids_session(timeout=1):
    key = ed25519.Ed25519PrivateKey.generate()
    store = SimpleNamespace(data={'ids_id': str(uuid.uuid4())}, sign=lambda lane: key,
                            peer_keys=lambda lane: (None, key.public_key().public_bytes_raw()),
                            peer_notifies=lambda: {})
    normal = SimpleNamespace(error=None, announce=AsyncMock(), sessions={lane: SimpleNamespace(local_address=bytes(16))
                                                   for lane in ('d', 'c')})
    ids = IdsSession(normal, store, lambda *a, **k: None, timeout)
    ids.nwsc_keys = {lane: (0, key.public_key().public_bytes_raw()) for lane in ('d', 'c')}
    return ids, key


def message(topic, kind, payload=b'', **updates):
    return {'event': 'message', 'topic': topic, 'type': kind, 'payload': payload,
            'id': str(uuid.uuid4()), 'peer': '', 'response': False, 'flags': 0, **updates}


class PreflightChecks(unittest.IsolatedAsyncioTestCase):
    async def test_nwsc_advertises_listener_instead_of_ephemeral_tcp_source(self):
        for port, service in ((61314, 'idstest/localdelivery/UTunDelivery-Default-Urgent-D'),
                              (61315, 'ids-control-channel')):
            ids, key = ids_session()
            reader, writer = asyncio.StreamReader(), Writer()
            writer.get_extra_info = lambda name: ('::1', 23456)
            reader.feed_data(nwsc_feedback(123, key.public_key().public_bytes_raw()))
            ids.connect = AsyncMock(return_value=(reader, writer))
            await ids.open('d', port, service)
            request = writer.written[0]
            self.assertEqual(int.from_bytes(request[2:4], 'big'), port)
            self.assertNotEqual(int.from_bytes(request[2:4], 'big'), 23456)
            self.assertEqual(nwsc_accept(request, key.public_key().public_bytes_raw())[0], service)

    async def test_rejected_wake_preserves_watch_setup_received_during_admission(self):
        ids, _ = ids_session()
        ids.control = Writer()
        name = 'UTunDelivery-Default-Urgent-D'
        async def admission(*args):
            self.assertNotIn(name, ids.setups)
            await ids.accept_setup({'kind': 2, 'guid': str(uuid.uuid4()), 'peer_guid': '',
                'local_port': 61314, 'remote_port': 61314, 'name': name})
            raise ValueError('Watch rejected NWSC service')
        ids.open = admission
        await ids.wake_class_d()
        self.assertTrue(ids.setups[name]['established'])
        self.assertEqual(ids.control.written[0][2], 2)
        self.assertTrue(ids.setups[name]['await_incoming'])

    async def test_rejected_wake_probes_four_endpoints_before_one_control_recovery(self):
        ids, _ = ids_session()
        ids.allow_wake_recovery = True
        ids.listen_only = True
        order = []
        async def probe(lane, port):
            order.append((lane, port))
        async def control(**kwargs):
            self.assertEqual(order, [('d', 61314), ('d', 61315), ('c', 61314), ('c', 61315)])
            self.assertEqual(kwargs, {'recovery': True})
            order.append('control')
        ids.discover_nwsc_key = AsyncMock(side_effect=probe)
        ids.open_control = AsyncMock(side_effect=control)
        await ids.recover_rejected_wake()
        await ids.recover_rejected_wake()
        ids.open_control.assert_awaited_once()

    async def test_rejected_wake_probe_failure_cannot_start_control(self):
        ids, _ = ids_session()
        ids.allow_wake_recovery = True
        ids.discover_nwsc_key = AsyncMock(side_effect=TimeoutError())
        ids.open_control = AsyncMock()
        await ids.recover_rejected_wake()
        ids.open_control.assert_not_awaited()
        self.assertEqual(ids.phase, 'waiting_incoming_control')

    async def test_handshake_accepts_any_uint32(self):
        for version in (0, 1, 2, 0xffffffff):
            ids, _ = ids_session()
            writer = Writer()
            await ids.accept_frame('d', writer, 4, struct.pack('>I', version), {})
            self.assertEqual(writer.written, [bytes.fromhex('040000000400000001')])
        with self.assertRaises(ValueError):
            await ids.accept_frame('d', Writer(), 4, b'\0' * 3, {})

    async def test_active_services_drop_late_nwsc_feedback(self):
        for control in (False, True):
            ids, key = ids_session()
            reader = asyncio.StreamReader()
            body = b'\x01hello' if control else struct.pack('>I', 1)
            wire = len(body).to_bytes(2, 'big') + body if control else frame(4, body)
            reader.feed_data(nwsc_feedback(123, key.public_key().public_bytes_raw()) + wire)
            reader.feed_eof()
            command, received = await ids.read_service_frame(reader, control=control)
            self.assertEqual(command, 1 if control else 4)
            self.assertEqual(received, body)
            self.assertTrue(reader.at_eof())

    async def test_direct_message_info_before_hello_is_not_fatal_or_echoed(self):
        ids, _ = ids_session()
        reader, writer = asyncio.StreamReader(), Writer()
        ids.control = writer
        # Source treats DirectMsgInfo as an announcement, including before Hello.
        peer_info = control_frame(b'\x0e\x04' + bytes(15))
        reader.feed_data(peer_info + hello(str(uuid.uuid4()), uuid.uuid4()))
        task = asyncio.create_task(ids.read_control_loop(reader, writer))
        try:
            await asyncio.wait_for(ids.hello_ready.wait(), 1)
            self.assertIsNone(ids.error)
            self.assertIsNotNone(ids.peer_hello)
            self.assertEqual(writer.written, [control_frame(b'\x0e\x01' + bytes(15))])
            self.assertNotIn(peer_info, writer.written)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_local_hello_advertises_reference_basic_direct_messaging(self):
        cursor = Cursor(hello(str(uuid.uuid4()), uuid.uuid4())[2:])
        self.assertEqual(cursor.number(1), 1)
        for _ in range(5):
            cursor.string(2)
        cursor.number(4)
        fields = tlvs(cursor.take(len(cursor.data) - cursor.offset))
        self.assertEqual(int.from_bytes(fields[3], 'big'), 0x3ff | 0x800)

    async def test_setup_transport_quiet_waits_for_tcp_and_does_not_fail_open(self):
        ids, _ = ids_session(timeout=0.1)
        ids.normal.link = SimpleNamespace(ertm=SimpleNamespace(pending=None))
        writer = Writer()
        writer.get_extra_info = lambda name: SimpleNamespace(fileno=lambda: 123)
        writer.transport = SimpleNamespace(get_write_buffer_size=lambda: 0)
        ids.control = writer
        queued = 100
        with patch('ids_session.fcntl.ioctl', side_effect=lambda *args: struct.pack('i', queued)):
            task = asyncio.create_task(ids.wait_transport_quiet())
            await asyncio.sleep(0.02)
            self.assertFalse(task.done())
            queued = 0
            await task
            queued = 100
            with self.assertRaisesRegex(TimeoutError, 'did not become quiet'):
                await ids.wait_transport_quiet()

    async def test_setup_ack_milestones_require_expected_lane_and_check_has_zero_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            flow.peer_info = flow.local_info_ack = True
            await flow.advance()
            self.assertEqual(ids.sent[-1].get('flags', 0), 0)
            await flow.accept({'event': 'ack', 'sequence': flow.check['sequence'], 'lane': 'c'})
            self.assertIsNone(flow.snapshot)
            await flow.accept({'event': 'ack', 'sequence': flow.check['sequence'], 'lane': 'd'})
            self.assertIsNotNone(flow.snapshot)
            await flow.accept({'event': 'ack', 'sequence': flow.snapshot['sequence'], 'lane': 'd'})
            self.assertIsNone(flow.property_request)
            await flow.accept({'event': 'ack', 'sequence': flow.snapshot['sequence'], 'lane': 'c'})
            self.assertIsNotNone(flow.property_request)

    async def test_runtime_configure_flags_and_activation_reply_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            proxy = SimpleNamespace(relay=AsyncMock(return_value=b'activation response'))
            flow = SetupFlow(ids, store, lambda *a, **k: None, proxy, 'Watch7,14')
            flow.property_request = {'sequence': 10}
            flow.watch = {'productType': 'Watch7,14', 'modelNumber': 'test',
                          'chipID': 1, 'capabilities': [str(uuid.uuid4())]}
            await flow.advance()
            modes = [sent for sent in ids.sent if sent['topic'] == NANO_D and sent['type'] == 3]
            self.assertEqual(len(modes), 2)
            self.assertTrue(all(sent.get('flags', 0) == 0 for sent in modes))
            request = message(PBB, 2, field(1, b'activation request'), flags=0)
            await flow.accept(request)
            self.assertEqual(ids.sent[-1]['peer'], request['id'])

    async def test_repeated_device_info_requires_new_ack_and_bounds_pending_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            request = message(CREDS, None, bplist({'command': 11, 'unique-id': str(uuid.uuid4())}))
            flow.local_info_ack = True
            await flow.accept(request)
            self.assertFalse(flow.local_info_ack)
            for _ in range(31):
                await flow.accept(request)
            with self.assertRaisesRegex(ValueError, 'Too many pending'):
                await flow.accept(request)

    async def test_device_info_uses_data_envelope_and_answers_repeated_requests(self):
        wire = application(1, 1, CREDS, str(uuid.uuid4()), b'payload')
        self.assertEqual(wire[0], 0)
        self.assertEqual(parse_application(0, wire[5:], {})['peer'], '')
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            request = message(CREDS, None, bplist({'command': 11, 'unique-id': str(uuid.uuid4())}))
            await flow.accept(request)
            await flow.accept(request)
            self.assertEqual(len(ids.sent), 2)
            self.assertTrue(all(not item.get('peer') for item in ids.sent))

    async def test_peer_stream_mapping_controls_reply_and_is_separate_from_local_ids(self):
        ids, _ = ids_session()
        writer = Writer()
        ids.lanes['d'] = writer
        await ids.send(CREDS, None, b'local request')
        first = parse_application(0, writer.written[-1][5:], {})
        self.assertEqual(first['stream'], 1)
        self.assertTrue(first['flags'] & 16)
        incoming = application(12, 42, CREDS, str(uuid.uuid4()), b'watch request')
        await ids.accept_frame('d', writer, 0, incoming[5:], {})
        self.assertEqual(ids.maps, {1: CREDS})
        self.assertEqual(ids.outgoing_maps, {42: CREDS})
        await ids.send(CREDS, None, b'local reply')
        reply = parse_application(0, writer.written[-1][5:], {42: CREDS})
        self.assertEqual(reply['stream'], 42)
        self.assertFalse(reply['flags'] & 16)
        topicless = application(13, 1, CREDS, str(uuid.uuid4()), b'watch reply', include_topic=False)
        await ids.accept_frame('d', writer, 0, topicless[5:], {})
        self.assertEqual((await ids.receive())['payload'], b'watch request')
        self.assertEqual((await ids.receive())['payload'], b'watch reply')
        with self.assertRaises(ValueError):
            ids.learn_peer_stream(42, PBB)

    async def test_service_map_updates_outgoing_direction_and_advertises_local_id(self):
        ids, _ = ids_session()
        writer = Writer()
        await ids.accept_frame('d', writer, 39, encode_tlvs({1: b'\x01',
            2: (42).to_bytes(2, 'big'), 3: CREDS.encode()}), {})
        self.assertEqual(ids.stream_for(CREDS), 42)
        self.assertEqual(ids.maps, {})
        for sequence in range(3):
            incoming = application(sequence, 42, CREDS, str(uuid.uuid4()), b'request')
            await ids.accept_frame('d', writer, 0, incoming[5:], {})
        advertisements = [wire for wire in writer.written if wire[0] == 39]
        self.assertEqual(len(advertisements), 1)
        fields = tlvs(advertisements[0][5:])
        self.assertEqual(fields[2], (1).to_bytes(2, 'big'))

    async def test_ids_cleanup_cancels_clients_before_waiting_for_listener(self):
        ids, key = ids_session()
        server = await asyncio.start_server(lambda r, w: ids.spawn(ids.accept_connection('d', r, w)), '::1', 0)
        ids.servers.append(server)
        writer = None
        try:
            reader, writer = await asyncio.open_connection('::1', server.sockets[0].getsockname()[1])
            writer.write(nwsc_probe(61315, 1, key))
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(44), 1)
            # Watch keeps its probe stream open: listener wait_closed must
            # not precede cancellation of the task owning that connection.
            await asyncio.wait_for(ids.close(), 1)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def test_incoming_control_verification_prevents_outgoing_request_race(self):
        ids, key = ids_session()
        ids.nwsc_keys.clear()
        connected, release_connect = asyncio.Event(), asyncio.Event()
        probing, release_probe = asyncio.Event(), asyncio.Event()
        outgoing_writer, incoming_writer = Writer(), Writer()
        async def connect(*args):
            connected.set()
            await release_connect.wait()
            return asyncio.StreamReader(), outgoing_writer
        async def discover(lane, port):
            probing.set()
            await release_probe.wait()
            ids.observe_nwsc_feedback(lane, nwsc_feedback(100, key.public_key().public_bytes_raw()))
        ids.connect = connect
        ids.discover_nwsc_key = discover
        ids.read_control_loop = AsyncMock()
        outgoing = asyncio.create_task(ids.open('d', 61315, 'ids-control-channel'))
        await connected.wait()
        reader = asyncio.StreamReader()
        reader.feed_data(nwsc_start(61315, 1, 'ids-control-channel', key, bytes(16)))
        incoming = asyncio.create_task(ids.accept_connection('d', reader, incoming_writer))
        try:
            await probing.wait()
            release_connect.set()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            self.assertFalse(outgoing_writer.written)
            release_probe.set()
            await asyncio.wait_for(incoming, 1)
            result = await asyncio.gather(outgoing, return_exceptions=True)
            self.assertIsInstance(result[0], asyncio.CancelledError)
            self.assertEqual(incoming_writer.written[0][2], 0x80)
            self.assertFalse(outgoing_writer.written)
            self.assertIsNone(ids.error)
        finally:
            outgoing.cancel()
            incoming.cancel()
            await asyncio.gather(outgoing, incoming, return_exceptions=True)
            await ids.close()

    async def test_concurrent_nrlp_senders_cannot_interleave_chunks(self):
        sent = []
        first_chunk = asyncio.Event()
        release = asyncio.Event()
        async def send(chunk):
            sent.append(chunk)
            if len(sent) == 1:
                first_chunk.set()
                await release.wait()
        ertm = SimpleNamespace(send=send, receive=AsyncMock(side_effect=asyncio.CancelledError))
        link = RelayLink(ertm, lambda *a, **k: None)
        large = b'A' * 1250
        small = b'B' * 58
        first = asyncio.create_task(link.send_message(4, large))
        await first_chunk.wait()
        second = asyncio.create_task(link.send_message(4, small))
        await asyncio.sleep(0)
        self.assertEqual(len(sent), 1)
        release.set()
        try:
            await asyncio.gather(first, second)
            wire = b''.join(sent)
            self.assertEqual(wire, build_inner_message(large, 4) + build_inner_message(small, 4))
            self.assertEqual(Stream().feed(wire), [(4, large), (4, small)])
        finally:
            await link.close()

    async def test_nwsc_uuid_collision_matches_connector_order(self):
        for local, remote, accepted in ((bytes(16), b'\xff' * 16, True), (b'\xff' * 16, bytes(16), False)):
            ids, key = ids_session()
            cancelled = []
            ids.pending_nwsc[('d', 'ids-control-channel')] = {
                'uuid': local, 'sent': True, 'task': SimpleNamespace(cancel=lambda: cancelled.append(True))}
            ids.read_control_loop = AsyncMock()
            reader, writer = asyncio.StreamReader(), Writer()
            reader.feed_data(nwsc_start(61315, 1, 'ids-control-channel', key, remote))
            await ids.accept_connection('d', reader, writer)
            self.assertEqual(writer.written[0][2], 0x80 if accepted else 0)
            self.assertEqual(bool(cancelled), accepted)
            self.assertIsNone(ids.error)

    async def test_invalid_nwsc_signature_rejects_only_that_connection(self):
        ids, key = ids_session()
        ids.nwsc_keys['d'] = (100, key.public_key().public_bytes_raw())
        other = ed25519.Ed25519PrivateKey.generate()
        reader, writer = asyncio.StreamReader(), Writer()
        ids.discover_nwsc_key = AsyncMock()  # the single re-probe returns the same key
        reader.feed_data(nwsc_start(61315, 1, 'ids-control-channel', other))
        await ids.accept_connection('d', reader, writer)
        self.assertEqual(writer.written[0][2], 0)
        self.assertIsNone(ids.error)
        self.assertIsNone(ids.control)
        ids.discover_nwsc_key.assert_awaited_once()

    async def test_normal_and_cloud_listeners_keep_separate_nwsc_keys(self):
        ids, _ = ids_session()
        ids.nwsc_keys = {}
        normal, cloud = (ed25519.Ed25519PrivateKey.generate() for _ in range(2))
        public = lambda k: k.public_key().public_bytes_raw()
        async def probe(lane, port):
            ids.nwsc_slot_keys[(lane, port)] = (1, public(normal if port == 61314 else cloud))
            ids.nwsc_keys[lane] = ids.nwsc_slot_keys[(lane, port)]
        ids.discover_nwsc_key = probe
        for port, signer, name in ((61315, cloud, 'UrgentCloud'), (61314, normal, 'Urgent')):
            sequence = 1  # not newer than the cached key, so only separate per-listener slots can verify it
            reader, writer = asyncio.StreamReader(), Writer()
            reader.feed_data(nwsc_start(port, sequence, f'idstest/localdelivery/UTunDelivery-Default-{name}-C', signer))
            await ids.accept_connection('c', reader, writer, port)
            self.assertEqual(writer.written[0][2], 0x80)

    async def test_watch_initiated_data_service_over_real_tcp(self):
        ids, key = ids_session()
        name = 'UTunDelivery-Default-Urgent-D'
        ids.control = Writer()
        incoming = {'kind': 2, 'guid': str(uuid.uuid4()), 'peer_guid': '', 'local_port': 61314,
                    'remote_port': 61314, 'name': name}
        await ids.accept_setup(incoming)
        ids.connect = AsyncMock(side_effect=AssertionError('Plain Watch Setup must not create an outgoing TCP'))
        server = await asyncio.start_server(
            lambda r, w: ids.spawn(ids.accept_connection('d', r, w, 61314)), '::1', 0)
        writer = None
        try:
            reader, writer = await asyncio.open_connection('::1', server.sockets[0].getsockname()[1])
            writer.write(nwsc_start(61314, 777, 'idstest/localdelivery/' + name, key))
            await writer.drain()
            feedback = await asyncio.wait_for(reader.readexactly(44), 1)
            self.assertEqual(parse_nwsc_feedback(feedback)[0], 0x80)
            self.assertEqual(await reader.readexactly(9), bytes.fromhex('040000000400000001'))
            self.assertFalse(ids.lane_ready['d'].is_set())
            writer.write(bytes.fromhex('040000000400000001'))
            await writer.drain()
            await asyncio.wait_for(ids.lane_ready['d'].wait(), 1)
            self.assertIsNone(ids.error)
            ids.connect.assert_not_awaited()
        finally:
            await ids.close()
            if writer:
                writer.close()
                await writer.wait_closed()
            server.close()
            await server.wait_closed()

    async def test_encrypted_reply_keeps_reciprocal_ports_despite_guid_order(self):
        ids, _ = ids_session()
        name = 'UTunDelivery-Default-Urgent-D'
        guid = 'ffffffff-ffff-4fff-bfff-ffffffffffff'
        ids.setups[name] = {'guid': guid, 'local_port': 16000, 'remote_port': 61314, 'established': False}
        ids.open_lane = AsyncMock()
        await ids.accept_setup({'kind': 6, 'guid': '00000000-0000-4000-8000-000000000000',
            'peer_guid': guid, 'local_port': 61314, 'remote_port': 16000, 'name': name})
        self.assertEqual((ids.setups[name]['local_port'], ids.setups[name]['remote_port']), (16000, 61314))
        await asyncio.sleep(0)

    async def test_incomplete_resource_has_no_application_ack(self):
        ids, _ = ids_session()
        writer = Writer()
        message = {'id': str(uuid.uuid4()), 'payload': b'chunk', 'flags': 4,
                   'sequence': 3, 'topic': 'resource'}
        with patch('ids_session.parse_application', return_value=message), patch('ids_session.save_resource', return_value=(5, 10)):
            await ids.accept_frame('d', writer, 22, b'', {})
        self.assertFalse(writer.written)

    async def test_watch_plain_setups_reply_without_phone_connections(self):
        ids, _ = ids_session()
        ids.control = Writer()
        ids.open_lane = AsyncMock()
        for priority in ('Urgent', 'Default', 'Sync'):
            for lane in ('C', 'D'):
                values = [str(uuid.uuid4()), '', 'idstest', 'localdelivery',
                          'UTunDelivery-Default-' + priority + '-' + lane]
                encoded = [value.encode() for value in values]
                # Independent layout of the Setup channel message, not our encoder.
                body = struct.pack('>BBHH5H', 2, 6, 61314, 61314, *map(len, encoded)) + b''.join(encoded)
                incoming = parse_setup(body)
                await ids.accept_setup(incoming)
                reply = parse_setup(ids.control.written[-1][2:])
                self.assertEqual(reply['kind'], 2)
                self.assertEqual(reply['peer_guid'], incoming['guid'])
                self.assertEqual((reply['local_port'], reply['remote_port']), (61314, 61314))
                self.assertTrue(ids.setups[incoming['name']]['await_incoming'])
        await asyncio.sleep(0)
        ids.open_lane.assert_not_awaited()
        self.assertEqual(len(ids.setups), 6)
        self.assertFalse(ids.lanes)

    async def test_direct_setup_reply_preserves_ports_and_flags(self):
        ids, _ = ids_session()
        ids.control = Writer()
        encoded = [v.encode() for v in [str(uuid.uuid4()), '', 'idstest', 'localdelivery',
                                        'UTunDelivery-Default-Urgent-D']]
        flags = bytes.fromhex('0000000100000002')
        body = struct.pack('>BBHH5H', 13, 6, 61314, 61314, *map(len, encoded)) + b''.join(encoded) + flags
        await ids.accept_setup(parse_setup(body))
        reply = parse_setup(ids.control.written[0][2:])
        self.assertEqual(reply['direct_flags'], flags)
        self.assertEqual(reply['kind'], 13)

    async def test_encrypted_setup_waits_for_ack_and_opens_once(self):
        ids, _ = ids_session()
        name = 'UTunDelivery-Default-Urgent-D'
        guid = str(uuid.uuid4())
        ids.setups[name] = {'guid': guid, 'local_port': 16000, 'remote_port': 61314,
                            'established': False}
        ids.open_lane = AsyncMock()
        self.assertFalse(ids.connecting_services)
        incoming = {'kind': 6, 'guid': str(uuid.uuid4()), 'peer_guid': guid,
                    'local_port': 61314, 'remote_port': 16000, 'name': name}
        await ids.accept_setup(incoming)
        await ids.accept_setup(incoming)
        await asyncio.sleep(0)
        ids.open_lane.assert_awaited_once_with('d', 'idstest/localdelivery/' + name)

    async def test_data_lane_waits_for_peer_handshake(self):
        for incoming in (False, True):
            ids, _ = ids_session()
            name = 'UTunDelivery-Default-Urgent-D'
            ids.setups[name] = {'established': True}
            reader, writer = asyncio.StreamReader(), Writer()
            task = asyncio.create_task(ids.attach('d', 'idstest/localdelivery/' + name,
                                                  reader, writer, incoming=incoming))
            try:
                await asyncio.sleep(0)
                self.assertFalse(ids.lane_ready['d'].is_set())
                self.assertEqual(len(writer.written), int(incoming))
                reader.feed_data(bytes.fromhex('040000000400000001'))
                await asyncio.wait_for(ids.lane_ready['d'].wait(), 1)
                self.assertEqual(writer.written, [bytes.fromhex('040000000400000001')])
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await ids.close()

    async def test_noop_response_waits_for_watch_fin(self):
        ids, key = ids_session()
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(nwsc_probe(61315, 1, key))
        task = asyncio.create_task(ids.accept_connection('d', reader, writer))
        try:
            await writer.draining.wait()
            await asyncio.sleep(0)
            self.assertFalse(writer.closed)
            self.assertFalse(task.done())
            reader.feed_eof()
            await asyncio.wait_for(task, 1)
            self.assertTrue(writer.closed)
            self.assertIsNone(ids.error)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_nwsc_retry_reconnects_with_same_uuid_and_new_sequence(self):
        ids, key = ids_session()
        writers, readers = [], []
        async def connect(lane, port):
            writer, reader = Writer(), asyncio.StreamReader()
            source_port = 15000 + len(writers)
            writer.get_extra_info = lambda name: ('::1', source_port)
            writers.append(writer)
            readers.append(reader)
            return reader, writer
        ids.connect = connect
        task = asyncio.create_task(ids.open('d', 61315, 'ids-control-channel'))
        try:
            while not writers or not writers[0].written:
                await asyncio.sleep(0)
            ids.pending_nwsc[('d', 'ids-control-channel')]['retry'].set()
            while len(writers) < 2 or not writers[1].written:
                await asyncio.sleep(0)
            readers[1].feed_data(nwsc_feedback(123, key.public_key().public_bytes_raw()))
            await asyncio.wait_for(task, 1)
            first, second = (writer.written[0] for writer in writers)
            self.assertEqual(first[12:28], second[12:28])
            self.assertLess(int.from_bytes(first[4:12], 'big'), int.from_bytes(second[4:12], 'big'))
            self.assertEqual(int.from_bytes(first[2:4], 'big'), 61315)
            self.assertEqual(int.from_bytes(second[2:4], 'big'), 15001)
            self.assertTrue(writers[0].closed)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await ids.close()

    async def test_nwsc_reverse_probe_reaches_outgoing_source_port(self):
        ids, key = ids_session()
        ids.normal.sessions['d'].local_address = ipaddress.IPv6Address('::1').packed
        ids.normal.sessions['d'].remote_address = ipaddress.IPv6Address('::1').packed
        received = asyncio.Event()
        accepted = []
        async def peer(reader, writer):
            accepted.append(writer)
            received.set()
        server = await asyncio.start_server(peer, '::1', 0)
        writer = reverse = None
        try:
            _, writer = await ids.connect('d', server.sockets[0].getsockname()[1])
            await asyncio.wait_for(received.wait(), 1)
            reader, reverse = await asyncio.open_connection('::1', writer.get_extra_info('sockname')[1])
            reverse.write(nwsc_probe(15001, 2, key))
            await reverse.drain()
            feedback = await asyncio.wait_for(reader.readexactly(44), 1)
            self.assertEqual(parse_nwsc_feedback(feedback)[0], 0)
            self.assertIsNone(ids.error)
        finally:
            for connection in [writer, reverse, *accepted]:
                if connection:
                    connection.close()
                    await connection.wait_closed()
            server.close()
            await server.wait_closed()
            await ids.close()

    async def test_nwsc_discovers_separate_key_before_verifying_service(self):
        ids, enrolled = ids_session()
        ids.nwsc_keys.clear()
        nwsc_key = ed25519.Ed25519PrivateKey.generate()
        stream = asyncio.StreamReader()
        stream.feed_data(nwsc_start(15001, 1, 'ids-control-channel', nwsc_key))
        async def discover(lane, port):
            self.assertEqual(port, 61315)
            # Feedback sequence versions the NWSC key; it is not a request echo.
            ids.observe_nwsc_feedback(lane, nwsc_feedback(938, nwsc_key.public_key().public_bytes_raw()))
        ids.discover_nwsc_key = AsyncMock(side_effect=discover)
        ids.read_control_loop = AsyncMock()
        writer = Writer()
        await ids.accept_connection('d', stream, writer)
        ids.discover_nwsc_key.assert_awaited_once()
        self.assertIsNone(ids.error)
        self.assertEqual(writer.written[0][2], 0x80)
        with self.assertRaises(Exception):
            nwsc_accept(nwsc_start(15001, 2, 'ids-control-channel', enrolled), nwsc_key.public_key().public_bytes_raw())

    async def test_nwsc_noop_publishes_key_without_claiming_service(self):
        ids, key = ids_session()
        request = nwsc_probe(15001, 123, key)
        self.assertEqual(len(request), 81)
        key.public_key().verify(request[16:80], request[:16] + bytes(64) + request[80:])
        stream = asyncio.StreamReader()
        stream.feed_data(request)
        stream.feed_eof()
        writer = Writer()
        await ids.accept_connection('d', stream, writer)
        flags, sequence, public = parse_nwsc_feedback(writer.written[0])
        self.assertEqual(flags, 0)
        self.assertEqual(public, key.public_key().public_bytes_raw())
        self.assertIsNone(ids.control)
        self.assertIsNone(ids.error)

    async def test_ids_listeners_precede_link_director_and_control_connect(self):
        ids, _ = ids_session()
        order = []
        async def listener(*args):
            order.append('listener')
            return SimpleNamespace(close=lambda: None, wait_closed=AsyncMock())
        async def announce():
            self.assertEqual(len(ids.servers), 4)
            order.append('announce')
            raise RuntimeError('offline startup stop')
        ids.normal.announce = announce
        ids.open_control = AsyncMock()
        with patch('ids_session.asyncio.start_server', new=listener):
            with self.assertRaisesRegex(RuntimeError, 'offline startup stop'):
                await ids.start()
        self.assertEqual(order, ['listener'] * 4 + ['announce'])
        ids.open_control.assert_not_awaited()

    async def test_normal_link_holds_early_ip_until_ids_attachment(self):
        from unittest.mock import Mock
        src, dst = PREFIX + b'R' * 6, PREFIX + b'L' * 6
        ready = asyncio.Event()
        ready.set()
        sessions = {lane: SimpleNamespace(local_address=dst if lane == 'd' else class_c(dst),
                    remote_address=src if lane == 'd' else class_c(src),
                    establish=AsyncMock(), authenticate=AsyncMock(), remote_unlocked=ready,
                    exchange=AsyncMock(return_value=(0, b''))) for lane in ('d', 'c')}
        tun = SimpleNamespace(start=Mock(), deliver=Mock(), name='offline')
        link = SimpleNamespace(timeout=.1, deferred=[])
        normal = NormalLink(link, lambda *a, **k: None, SimpleNamespace(save=Mock()), None, None)
        normal.pending_ip = [b'previously authenticated early IP']
        with patch('normal_link.OrdinarySession', side_effect=lambda link, record, store, lane, *a: sessions[lane]), \
                patch('normal_link.Tun', return_value=tun):
            await normal.start()
        self.assertFalse(normal.accept_ip)
        tun.deliver.assert_not_called()
        normal.outgoing = AsyncMock()
        await normal.announce()
        tun.deliver.assert_called_once_with(b'previously authenticated early IP')
        self.assertTrue(normal.accept_ip)
        self.assertEqual(normal.pending_ip, [])
        self.assertEqual(normal.outgoing.await_count, 2)
        for call, lane in zip(normal.outgoing.await_args_list, ('d', 'c')):
            packet = call.args[0]
            session = sessions[lane]
            self.assertEqual(packet[:8], bytes.fromhex('6000000000183aff'))
            self.assertEqual(packet[8:40], session.local_address + session.remote_address)
            self.assertEqual(packet[40:42], b'\x88\0')
            self.assertEqual(packet[44:48], b'\x20\0\0\0')
            self.assertEqual(packet[48:], session.local_address)
            pseudo = packet[8:40] + struct.pack('>I3xB', 24, 58) + packet[40:]
            total = sum(struct.unpack('>' + 'H' * (len(pseudo) // 2), pseudo))
            while total >> 16:
                total = (total & 0xffff) + (total >> 16)
            self.assertEqual(total, 0xffff)

    async def test_authenticated_noncanonical_esp_padding(self):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        keys = derive_sa_init_keys(b'S' * 56, b'I' * 32, b'R' * 32, b'INITIATR', b'RESPONDR')
        receiver = Esp(keys, b'I' * 32, b'R' * 32, b'peer', b'host')
        addresses = PREFIX + b'R' * 6 + PREFIX + b'L' * 6
        payload = bytes.fromhex('0102030405')  # Regression payload.
        def packet(sequence, plain):
            aad = b'peer' + struct.pack('>I', sequence)
            nonce = receiver.rx_key[32:] + bytes(4) + aad[4:]
            wire = aad + AESGCM(receiver.rx_key[:32]).encrypt(nonce, plain, aad)
            return struct.pack('>IHBB', 0x60000000, len(wire), 50, 64) + addresses + wire
        expected = struct.pack('>IHBB', 0x60000000, len(payload), 17, 64) + addresses + payload
        for seq, padding in enumerate((b'\0', b'\xff\0\x42', b'\xa5' * 255), 1):
            encrypted = packet(seq, payload + padding + bytes([len(padding), 17]))
            before = (list(receiver.highest), list(receiver.seen))
            with self.assertRaises(InvalidTag):
                receiver.open(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
            self.assertEqual((receiver.highest, receiver.seen), before)
            self.assertEqual(receiver.open(encrypted), expected)
            self.assertIsNone(receiver.open(encrypted))
        for plain in (b'', b'\0', b'\x05\x11'):
            before = (list(receiver.highest), list(receiver.seen))
            with self.assertRaises(ValueError):
                receiver.open(packet(4, plain))
            self.assertEqual((receiver.highest, receiver.seen), before)
        self.assertEqual(receiver.open(packet(4, payload + b'\0\x11')), expected)

    async def test_lowpan_templates_with_authenticated_esp(self):
        from cryptography.exceptions import InvalidTag
        source_d, destination_d = PREFIX + b'R' * 6, PREFIX + b'L' * 6
        keys = derive_sa_init_keys(b'S' * 56, b'I' * 32, b'R' * 32, b'INITIATR', b'RESPONDR')
        normal = NormalLink(None, lambda *a, **k: None, None, None, None)
        delivered = []
        normal.tun = SimpleNamespace(deliver=delivered.append)
        normal.accept_ip = True
        peers = {}
        for lane, spi in (('d', b'dddd'), ('c', b'cccc')):
            rx = Esp(keys, b'I' * 32, b'R' * 32, spi, b'host')
            tx = Esp(keys, b'I' * 32, b'R' * 32, b'host', spi)
            rx.rx_key = tx.tx_key
            src, dst = (source_d, destination_d) if lane == 'd' else (class_c(source_d), class_c(destination_d))
            normal.sessions[lane] = SimpleNamespace(esp=rx, remote_address=src, local_address=dst)
            peers[lane] = tx
        for second, lane in ((0x33, 'd'), (0x66, 'c'), (0x30, 'd'), (0x03, 'd'), (0, 'd')):
            session = normal.sessions[lane]
            src, dst = session.remote_address, session.local_address
            inline = {0x33: b'', 0x66: src[8:10] + dst[8:10], 0x30: src, 0x03: dst, 0: dst + src}[second]
            for traffic in (0, 2, 0xc0):
                clear = struct.pack('>IHBB', 0x60000000 | traffic << 20, 5, 6, 64) + src + dst + b'hello'
                encrypted = peers[lane].seal(clear)
                prefix = (bytes([0x7a, second, 50]) if traffic == 0
                          else bytes([0x72, second, traffic, 50]))
                compressed = prefix + inline + encrypted[40:]
                self.assertEqual(decode_lowpan(compressed, source_d, destination_d), encrypted)
                self.assertTrue(await normal.incoming(3, compressed))
                self.assertEqual(delivered[-1], clear)
        # The 79 1b link-local/multicast template must authenticate
        # before being discarded; a corrupt tag must still fail.
        src = bytes.fromhex('fe80000000000000') + b'R' * 8
        dst = bytes.fromhex('ff020000000000000000000000000001')
        clear = struct.pack('>IHBB', 0x60000000, 5, 6, 1) + src + dst + b'hello'
        compressed = b'\x79\x1b\x32' + src[8:] + b'\x01' + peers['d'].seal(clear)[40:]
        self.assertEqual(decode_lowpan(compressed, source_d, destination_d)[8:40], src + dst)
        with self.assertRaises(InvalidTag):
            await normal.incoming(3, compressed[:-1] + bytes([compressed[-1] ^ 1]))
        count = len(delivered)
        self.assertTrue(await normal.incoming(3, compressed))
        self.assertEqual(len(delivered), count)

    async def test_lowpan_rejects_truncation_and_unsupported_dispatch(self):
        source, destination = PREFIX + b'R' * 6, PREFIX + b'L' * 6
        valid = b'\x72\0\xc0\x32' + destination + source
        for size in range(len(valid)):
            with self.assertRaises(ValueError):
                decode_lowpan(valid[:size], source, destination)
        for invalid in (b'\x7e\x33\x32', b'\x7a\xb3\x32', b'\x62\x33\x32', b'\x00\x33\x32'):
            with self.assertRaises(ValueError):
                decode_lowpan(invalid, source, destination)

    async def test_pairing_channel_keeps_data_arriving_with_acceptance(self):
        await self.channel_run_check()

    async def test_resume_uses_completed_pairing_prelude_before_app_setup(self):
        await self.channel_run_check(resume=True)

    async def test_modern_prelude_requires_bilateral_state_compatibility(self):
        for paired in (False, True):
            local = prelude(paired=paired)
            remote = prelude(b'R' * 16, paired=paired)
            self.assertEqual(accept_prelude(remote, local), b'R' * 16)
            with self.assertRaisesRegex(ValueError, 'Incompatible normal-link pairing states'):
                accept_prelude(prelude(b'R' * 16, paired=not paired), local)

    async def test_sudo_artifacts_owned_by_invoking_user(self):
        with patch('pairing_store.os.geteuid', return_value=0), \
                patch.dict(os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), \
                patch('pairing_store.os.chown') as chown:
            user_owned(Path('/tmp/private-artifact'))
            chown.assert_called_once_with(Path('/tmp/private-artifact'), 1000, 1000, follow_symlinks=False)

    async def channel_run_check(self, resume=False):
        from bumble.device import Device
        from bumble.hci import Address
        from magnet_probe import MAGNET_CID, magnet, parse_magnet
        from nrlp import build_inner_message
        with tempfile.TemporaryDirectory() as directory:
            device = Device.with_hci('offline channel', Address('C2:02:03:04:05:06'), None, None)
            device.power_on = AsyncMock()
            connection = SimpleNamespace(handle=1, on=lambda *args: None, disconnect=AsyncMock(),
                                         encrypt=AsyncMock(), is_encrypted=True)
            device.connect = AsyncMock(return_value=connection)
            unexpected = []
            original = device.l2cap_channel_manager.on_pdu
            def fallback(conn, cid, packet):
                if cid == 64:
                    unexpected.append(packet)
                else:
                    original(conn, cid, packet)
            device.l2cap_channel_manager.on_pdu = fallback
            def send(cid, packet):
                dispatch = device.l2cap_channel_manager.on_pdu
                if cid != MAGNET_CID:
                    if resume and packet[2:].startswith(b'TERMINUS'):
                        self.assertEqual(packet[11], 20)
                        dispatch(connection, 65, b'\x01\x01')
                        dispatch(connection, 65, b'\0\x01' + prelude(b'R' * 16, paired=True))
                    return  # ERTM receipt for the buffered first frame.
                op, body = parse_magnet(packet)
                sid = 2 if resume else 1
                if op == 9:
                    dispatch(connection, MAGNET_CID, magnet(9, b'\x0b\x21\x15\0\0'))
                elif op == 1:
                    dispatch(connection, MAGNET_CID, magnet(2, struct.pack('<BH', 1, sid)))
                elif op == 3:
                    dispatch(connection, MAGNET_CID, magnet(4, struct.pack('<BHH', 0, sid, 775)))
                    # Same HCI callback batch: run() hasn't resumed to install its handler.
                    if not resume:
                        dispatch(connection, 64, b'\0\0' + build_inner_message(b'first frame'))
            connection.send_l2cap_pdu = send
            async def establish(session):
                if not resume:
                    self.assertEqual(await asyncio.wait_for(session.link.messages.get(), .2),
                                     (4, b'first frame'))
                raise RuntimeError('offline test stop')
            transport = SimpleNamespace(source=None, sink=None,
                                        __aenter__=AsyncMock(), __aexit__=AsyncMock())
            args = SimpleNamespace(scan=False, resume=resume, peer='42:02:03:04:05:06',
                                   address_type='random', setup_data='208837d4ce64385000d01000',
                                   product='Watch7,14', state=Path(directory) / 'state',
                                   output=Path(directory), transport='offline-mock', timeout=.5)
            if resume:
                Store(args.state).save(bonded=True, paired=False)
            with patch('bumble.transport.open_transport', new=AsyncMock(return_value=transport)), \
                    patch.object(Device, 'with_hci', return_value=device), \
                    patch.object(IkeSession, 'establish', new=establish), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'offline test stop'):
                    await run(args)
            self.assertEqual(unexpected, [])
            connection.disconnect.assert_awaited_once()

    async def test_key_enrollment_without_address_echo(self):
        # Construct the peer reply independently: no local_notifies() symmetry.
        from cryptography.hazmat.primitives.asymmetric import x25519
        batch = {0xc547: b'r' + b'R' * 16 + b'c' + b'C' * 16,
                 0xc4af: uuid.uuid4().bytes + x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()}
        for tag in (0xc548, 0xc549):
            batch[tag] = encode_tlvs({1: ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                                     2: x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()})
        spi_i, spi_r = b'INITIATR', b'RESPONDR'
        keys = derive_sa_init_keys(b'S' * 56, b'I' * 32, b'R' * 32, spi_i, spi_r)
        peer = Protected(spi_i, spi_r, keys, False)
        async def request(packets, accept):
            self.assertIsNotNone(peer.open(packets[0], 37, 5, response=False))
            self.assertIsNone(accept(peer.seal(37, 5, 0, b'', response=True)[0]))
            return accept(peer.seal(37, 0, 41, chain([(41, notify(tag, value))
                                                     for tag, value in batch.items()]))[0])
        session = IkeSession(SimpleNamespace(request=request), lambda *a, **k: None)
        session.initial = SimpleNamespace(initiator_spi=spi_i)
        session.protected = Protected(spi_i, spi_r, keys)
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            proposed = list(store.data['addresses'])
            notes, mid = await session.private_exchange(None, None, 5,
                                                       batch={0xc547: batch[0xc547]})
            self.assertEqual(mid, 0)
            store.enroll_peer(notes)
            saved = Store(directory)
            self.assertEqual(saved.data['stage'], 'keys_enrolled')
            self.assertEqual(saved.data['addresses'], proposed)
            self.assertEqual(saved.peer_notifies(), batch)
            self.assertFalse(saved.data.get('bonded', False))

    async def test_enrollment_rejects_bad_credentials_without_saving(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            valid = store.local_notifies(SimpleNamespace(r=b'R' * 16, c=b'C' * 16), 'Watch', '23T240')
            cases = []
            for tag in (0xc547, 0xc548, 0xc549, 0xc4af):
                missing = dict(valid)
                del missing[tag]
                cases.extend([missing, {**valid, tag: b''}])
            cases.extend([{**valid, 0xc547: b'x' + valid[0xc547][1:]},
                          {**valid, 0xc548: encode_tlvs({1: b'A' * 32, 3: b'B' * 32})},
                          {**valid, 0xc549: encode_tlvs({1: b'A' * 31, 2: b'B' * 32})},
                          {**valid, 0xc548: valid[0xc548] + valid[0xc548]}])
            original = dict(store.data)
            for batch in cases:
                with self.assertRaises(ValueError):
                    store.enroll_peer(batch)
                self.assertEqual(store.data, original)
                self.assertEqual(Store(directory).data, original)

    async def test_enrollment_preserves_opaque_metadata_and_key_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            batch = store.local_notifies(SimpleNamespace(r=b'R' * 16, c=b'C' * 16), 'Watch', '23T240')
            proposed = list(store.data['addresses'])
            # Unconsumed metadata must not impose an invented quartet/schema.
            for tag in (0xc672, 0xc67b, 0xc67c, 0xbdde, 0xc8c9, 0xbddc):
                del batch[tag]
            batch.update({0xc671: b'opaque', 0xbddb: b'\xff', 0xffff: b'extension'})
            batch[0xc548] += encode_tlvs({3: b'extension'})
            store.enroll_peer(batch)
            saved = Store(directory)
            self.assertEqual(saved.data['addresses'], proposed)
            self.assertEqual(saved.peer_notifies(), batch)

    async def test_scan_uses_matching_controller_command_family(self):
        from bumble.device import Device
        from bumble import hci
        for extended in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                device = Device.with_hci('offline scan', hci.Address('C2:02:03:04:05:06'), None, None)
                device.power_on = AsyncMock()
                device.send_sync_command = AsyncMock()
                transport = SimpleNamespace(source=None, sink=None,
                    __aenter__=AsyncMock(), __aexit__=AsyncMock())
                args = SimpleNamespace(scan=True, resume=False, peer=None, output=Path(directory),
                    transport='offline-mock', setup_data=None, timeout=0.001)
                with patch('bumble.transport.open_transport', new=AsyncMock(return_value=transport)), \
                        patch.object(Device, 'with_hci', return_value=device), \
                        patch.object(Device, 'supports_le_extended_advertising', new_callable=PropertyMock,
                                     return_value=extended), redirect_stdout(io.StringIO()):
                    await run(args)
                commands = [call.args[0] for call in device.send_sync_command.await_args_list]
                if extended:
                    self.assertIsInstance(commands[0], hci.HCI_LE_Set_Extended_Scan_Parameters_Command)
                    self.assertTrue(all(isinstance(cmd, hci.HCI_LE_Set_Extended_Scan_Enable_Command)
                                        for cmd in commands[1:]))
                    self.assertEqual([cmd.enable for cmd in commands[1:]], [1, 0])
                else:
                    self.assertIsInstance(commands[0], hci.HCI_LE_Set_Scan_Parameters_Command)
                    self.assertTrue(all(isinstance(cmd, hci.HCI_LE_Set_Scan_Enable_Command)
                                        for cmd in commands[1:]))
                    self.assertEqual([cmd.le_scan_enable for cmd in commands[1:]], [1, 0])
                transport.__aexit__.assert_awaited_once()

    async def test_installed_bumble_persistence_and_identity_ordering(self):
        try:
            import bumble
            from bumble.core import PhysicalTransport
            from bumble.device import Device
            from bumble.hci import Address
            from bumble.keys import JsonKeyStore
            from bumble import smp
        except ImportError:
            self.skipTest('Requires the pinned Bumble environment')
        self.assertEqual(bumble.__version__, '0.0.235')
        with tempfile.TemporaryDirectory() as directory:
            device = Device.with_hci('offline test', Address('C2:02:03:04:05:06'), None, None)
            device.keystore = JsonKeyStore(namespace='offline', filename=str(Path(directory) / 'bond.json'))
            paused, release = asyncio.Event(), asyncio.Event()
            async def refresh():
                paused.set()
                await release.wait()
            device.refresh_resolving_list = refresh
            manager = object.__new__(smp.Manager)
            manager.device = device
            connection = Connection()
            connection.EVENT_PAIRING = 'pairing'
            connection.peer_address = Address('42:02:03:04:05:06')
            connection.transport = PhysicalTransport.LE
            connection.drain = AsyncMock()
            identity = Address('C3:02:03:04:05:06')
            session = SimpleNamespace(completed=False, connection=connection,
                pairing_result=asyncio.get_running_loop().create_future(), peer_bd_addr=identity,
                ctkd_task=None, sc=True, pairing_method=smp.PairingMethod.OOB, ltk=bytes(range(16)),
                peer_identity_resolving_key=None, peer_signature_key=None, link_key=None, manager=manager)
            processing = []
            async def pair():
                processing.append(asyncio.create_task(smp.Session.on_pairing(session)))
                await session.pairing_result
            connection.pair = pair
            task = asyncio.create_task(finish_bond(connection, AsyncMock(), 1))
            try:
                await paused.wait()
                await asyncio.sleep(0)
                self.assertTrue(session.pairing_result.done())
                self.assertNotEqual(connection.peer_address, identity)
                self.assertFalse(task.done())
                release.set()
                await task
                self.assertEqual(connection.peer_address, identity)
                keys = await device.keystore.get(str(identity))
                self.assertTrue(keys.ltk.authenticated)
                self.assertEqual(keys.ltk.value, session.ltk)
            finally:
                task.cancel()
                for worker in processing:
                    worker.cancel()
                await asyncio.gather(task, *processing, return_exceptions=True)

    async def test_bond_waits_for_persisted_identity_event(self):
        connection = Connection()
        acknowledged = asyncio.Event()
        async def acknowledge():
            self.assertTrue(connection.started.is_set())
            acknowledged.set()
        task = asyncio.create_task(finish_bond(connection, acknowledge, 1))
        await acknowledged.wait()
        await asyncio.sleep(0)
        self.assertFalse(task.done())  # pair() already returned; persistence has not.
        connection.emit('pairing', object())
        await task
        self.assertFalse(connection.listeners)

    async def test_bond_event_before_pair_returns(self):
        connection = Connection()
        async def pair():
            connection.started.set()
            connection.emit('pairing', object())
        connection.pair = pair
        await finish_bond(connection, AsyncMock(), 1)
        self.assertFalse(connection.listeners)

    async def test_bond_failure_disconnect_and_ack_failure_cancel_smp(self):
        for event, details in [('pairing_failure', (5,)), ('disconnection', ())]:
            connection = Connection(blocked=True)
            task = asyncio.create_task(finish_bond(connection, AsyncMock(), 1))
            await connection.started.wait()
            connection.emit(event, *details)
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(task, 0.2)
            self.assertTrue(connection.cancelled)
            self.assertFalse(connection.listeners)
        connection = Connection(blocked=True)
        with self.assertRaisesRegex(RuntimeError, 'ack failed'):
            await finish_bond(connection, AsyncMock(side_effect=RuntimeError('ack failed')), 1)
        self.assertTrue(connection.cancelled)
        self.assertFalse(connection.listeners)

    async def test_bond_timeout_cleans_up(self):
        connection = Connection(blocked=True)
        with self.assertRaises(TimeoutError):
            await finish_bond(connection, AsyncMock(), 0.02)
        self.assertTrue(connection.cancelled)
        self.assertFalse(connection.listeners)

    async def test_incoming_control_survives_outgoing_refusal_or_timeout(self):
        for blocked in (False, True):
            ids, _ = ids_session()
            incoming = Writer()
            started = asyncio.Event()
            cancelled = asyncio.Event()
            async def open_control(*args):
                started.set()
                if blocked:
                    try:
                        await asyncio.Event().wait()
                    finally:
                        cancelled.set()
                raise ConnectionRefusedError('offline refusal')
            ids.open = open_control
            async def write(writer, data):
                for ready in ids.lane_ready.values():
                    ready.set()
                for joined in ids.lane_joined.values():
                    joined.set()
            ids.write = write
            server = SimpleNamespace(close=lambda: None, wait_closed=AsyncMock())
            try:
                with patch('ids_session.asyncio.start_server', new=AsyncMock(return_value=server)):
                    task = asyncio.create_task(ids.start())
                    await started.wait()
                    ids.control = incoming
                    ids.hello_ready.set()
                    await asyncio.wait_for(task, 0.2)
                self.assertIs(ids.control, incoming)
                self.assertIsNone(ids.error)
                if blocked:
                    self.assertTrue(cancelled.is_set())
            finally:
                await ids.close()

    async def test_simultaneous_incoming_control_has_one_winner(self):
        ids, key = ids_session()
        first, second = Writer(blocked=True), Writer()
        def reader(sequence):
            stream = asyncio.StreamReader()
            stream.feed_data(nwsc_start(15001, sequence, 'ids-control-channel', key))
            return stream
        control_read = AsyncMock()
        ids.read_control_loop = control_read
        task = asyncio.create_task(ids.accept_connection('d', reader(2), first))
        try:
            await first.draining.wait()  # First NWSC feedback has yielded.
            await ids.accept_connection('d', reader(1), second)
            self.assertIs(ids.control, first)
            self.assertEqual(second.written[0][2], 0)  # Reject stale competing route transiently.
            first.release.set()
            await task
            self.assertEqual(first.written[0][2], 0x80)
            control_read.assert_awaited_once()
            self.assertIsNone(ids.error)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await ids.close()

    async def test_outgoing_control_loses_to_incoming_claim(self):
        ids, _ = ids_session()
        first, outgoing = Writer(), Writer()
        async def open_control(*args):
            ids.control = first
            return object(), outgoing
        ids.open = open_control
        await ids.open_control()
        self.assertIs(ids.control, first)
        self.assertTrue(outgoing.closed)
        self.assertFalse(outgoing.written)

    async def test_outgoing_control_sends_hello_when_it_wins(self):
        ids, _ = ids_session()
        writer = Writer()
        ids.open = AsyncMock(return_value=(object(), writer))
        ids.read_control_loop = AsyncMock()
        try:
            await ids.open_control()
            await asyncio.sleep(0)
            self.assertIs(ids.control, writer)
            self.assertEqual(writer.written[0][2], 1)
            ids.read_control_loop.assert_awaited_once()
        finally:
            await ids.close()

    async def test_early_sync_completion_and_registry_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            flow.prepare = {'id': str(uuid.uuid4()).upper()}
            await flow.accept(message(PSY, 0, sync_state(True)))
            self.assertFalse(flow.sync_complete)
            await flow.accept(message(PBB, 18, peer=flow.prepare['id']))
            self.assertTrue(flow.sync_complete)
            self.assertFalse(flow.completion_ack)
            await flow.accept({'event': 'app_ack', 'topic': PSY, 'peer': flow.completion['id']})
            self.assertTrue(flow.completion_ack)
            await flow.accept(message(NANO_C, 2, nr_properties({'isSetup': True})))
            self.assertTrue(flow.is_setup)
            for value in (False, None):
                await flow.accept(message(NANO_C, 2, nr_properties({'isSetup': value})))
                self.assertFalse(flow.is_setup)

    async def test_full_setup_with_early_sync_and_registry_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'host')
            peer = Store(Path(directory) / 'watch')
            await setup_checks(store, peer, early_sync=True)
            self.assertTrue(store.data['setup_complete'])

    async def test_tun_failure_wakes_ids_and_stored_failure_is_immediate(self):
        normal = NormalLink(None, lambda *a, **k: None, None, None, None)
        ids = IdsSession(normal, None, lambda *a, **k: None, 1)
        read_fd, write_fd = os.pipe()
        tun = object.__new__(Tun)
        tun.fd, tun.error = read_fd, None
        error = RuntimeError('offline packet send failure')
        async def broken(packet):
            raise error
        tun.start(broken, normal.fail)
        waiting = asyncio.create_task(ids.receive())
        try:
            tun.queue.put_nowait(b'offline pipe packet')
            with self.assertRaisesRegex(RuntimeError, 'packet send failure'):
                await asyncio.wait_for(waiting, 0.2)
            self.assertIs(ids.error, error)
            for _ in range(2):
                with self.assertRaises(RuntimeError) as caught:
                    await ids.receive()
                self.assertIs(caught.exception, error)
            normal.on_error = None
            late = IdsSession(normal, None, lambda *a, **k: None)
            self.assertIs(late.error, error)
        finally:
            waiting.cancel()
            await asyncio.gather(waiting, return_exceptions=True)
            await tun.close()
            os.close(write_fd)

    async def test_irk_is_persistent_and_legacy_bond_identity_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            irk = store.key('host_irk')
            self.assertEqual(len(irk), 16)
            self.assertNotEqual(irk, bytes(16))
            self.assertEqual(Store(directory).key('host_irk'), irk)
            legacy = dict(store.data)
            del legacy['host_irk']
            store.path.write_text(json.dumps(legacy))
            (store.directory / 'bond.json').write_text('{}')
            self.assertEqual(Store(directory).key('host_irk'), bytes(16))

    async def test_tun_read_failure_wakes_ids(self):
        normal = NormalLink(None, lambda *a, **k: None, None, None, None)
        ids = IdsSession(normal, None, lambda *a, **k: None)
        read_fd, write_fd = os.pipe()
        tun = object.__new__(Tun)
        tun.fd, tun.error = read_fd, None
        with patch.object(asyncio.get_running_loop(), 'add_reader') as add_reader:
            tun.start(AsyncMock(), normal.fail)
            readable = add_reader.call_args.args[1]
        try:
            with patch('normal_link.os.read', side_effect=OSError('offline read failure')):
                readable()
            with self.assertRaisesRegex(OSError, 'read failure'):
                await ids.receive()
        finally:
            await tun.close()
            os.close(write_fd)

    async def test_invalid_account_rpc_is_observable_without_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids, events = FakeIds(store), []
            flow = SetupFlow(ids, store, lambda event, **details: events.append((event, details)), None, 'Watch7,14')
            await flow.accept(message(CREDS, None, bplist({'command': 17, 'unique-id': str(uuid.uuid4())})))
            self.assertFalse(ids.sent)  # malformed request (no serviceTypes): no reply, setup continues
            self.assertIn(('ids_credential_command_unsupported', {'command': 17, 'reason': 'service list'}), events)

    async def test_temporary_bond_file_is_ignored(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(['git', 'check-ignore', '--no-index', '-q', 'custom-state/bond.json.tmp'],
                                cwd=root, capture_output=True)
        self.assertEqual(result.returncode, 0)

    async def test_listen_only_and_policy_rejection_skip_outgoing_control(self):
        ids, _ = ids_session()
        ids.open = AsyncMock()
        ids.listen_only = True
        await ids.open_control()
        ids.open.assert_not_awaited()
        self.assertEqual(ids.phase, 'waiting_incoming_control')
        ids.listen_only = False
        ids.open = AsyncMock(side_effect=ValueError('Watch rejected NWSC service'))
        await ids.open_control()
        self.assertTrue(ids.control_policy_rejected)
        ids.open.reset_mock()
        await ids.open_control()
        ids.open.assert_not_awaited()

    async def test_class_d_wake_survives_policy_rejection(self):
        ids, _ = ids_session()
        ids.open = AsyncMock(side_effect=ValueError('Watch rejected NWSC service'))
        await ids.wake_class_d()
        self.assertIsNone(ids.error)
        self.assertEqual(ids.open.await_args.args[1:], (61314, 'idstest/localdelivery/UTunDelivery-Default-Urgent-D'))
        self.assertNotIn('UTunDelivery-Default-Urgent-D', ids.setups)

    async def test_watch_closing_outgoing_urgent_socket_waits_for_replacement(self):
        ids, _ = ids_session()
        name = 'UTunDelivery-Default-Urgent-D'
        ids.setups[name] = {'established': True}
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_eof()
        await ids.attach('d', 'idstest/localdelivery/' + name, reader, writer)
        self.assertIsNone(ids.error)
        for task in list(ids.tasks):
            task.cancel()

    async def test_account_fetch_gets_empty_accounts_and_sync_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            fetch, sync = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
            await flow.accept(message(CREDS, None, bplist(
                {'command': 17, 'unique-id': fetch, 'serviceTypes': ['com.apple.private.alloy.sharing']})))
            reply = __import__('plistlib').loads(ids.sent[-1]['payload'])
            self.assertEqual((reply['command'], reply['unique-id'], reply['accountMap']),
                             (18, fetch, {'com.apple.private.alloy.sharing': []}))
            await flow.accept(message(CREDS, None, bplist(
                {'command': 15, 'unique-id': sync, 'sync-payload': {'command': 5}})))
            reply = __import__('plistlib').loads(ids.sent[-1]['payload'])
            self.assertEqual((reply['command'], reply['unique-id'], reply['success']), (16, sync, True))  # SPS info acknowledged
            other = str(uuid.uuid4()).upper()
            await flow.accept(message(CREDS, None, bplist(
                {'command': 15, 'unique-id': other, 'sync-payload': {'command': 7}})))
            reply = __import__('plistlib').loads(ids.sent[-1]['payload'])
            self.assertEqual((reply['command'], reply['unique-id'], reply['success']), (16, other, False))

    async def test_unlimited_setup_timeout_keeps_ids_arithmetic_working(self):
        import math
        from watch_poc import ids_timeout
        self.assertEqual(ids_timeout(900), 900)
        limit = ids_timeout(math.inf)
        self.assertIsInstance(limit, float)
        self.assertGreater(1.5 + limit, 1.5)  # added to a loop time by IdsSession
        self.assertFalse(1.5 >= limit)  # compared against elapsed time by IdsSession

    async def test_dictionary_message_with_expiry_round_trips_on_the_wire(self):
        from ids_wire import application, parse_application
        wire = application(7, 3, 'com.apple.private.alloy.appsyncconduit.v2', str(uuid.uuid4()).upper(),
                           bplist({'T': 34}), flags=9, command=6, expiry=813247695, include_topic=True)
        self.assertEqual(wire[0], 6)
        message = parse_application(6, wire[5:], {})
        self.assertEqual((message['flags'], message['topic']), (25, 'com.apple.private.alloy.appsyncconduit.v2'))
        self.assertEqual(__import__('plistlib').loads(message['payload']), {'T': 34})
        self.assertEqual(int.from_bytes(wire[-4:], 'big'), 813247695)

    async def test_app_list_is_announced_once_when_the_watch_uses_the_app_sync_conduit(self):
        from apple_codec import APPSYNC
        from setup_flow import DEFAULT_WATCH_APPS
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            ids = FakeIds(store)
            flow = SetupFlow(ids, store, lambda *a, **k: None, None, 'Watch7,14')
            for _ in range(2):
                await flow.accept(message(APPSYNC, None, bplist({'T': 29})))
            sent = [item for item in ids.sent if item['topic'] == APPSYNC]
            self.assertEqual(len(sent), 2)  # one announcement of two messages, not repeated for later Watch messages
            plists = [__import__('plistlib').loads(item['payload']) for item in sent]
            self.assertEqual(plists, [{'T': 30, 'BL': DEFAULT_WATCH_APPS}, {'T': 34}])
            self.assertTrue(all(item['command'] == 6 and item['flags'] == 9 and item['expiry'] > 0 for item in sent))



if __name__ == '__main__':
    unittest.main()
