"""Modern IDS over the authenticated TUN, with signed NWSC admission."""
import asyncio
import contextlib
import fcntl
import ipaddress
import secrets
import socket
import struct
import time
import termios
import uuid
from cryptography.exceptions import InvalidSignature
from apple_codec import CLASS_D_TOPICS, LIMIT
from ids_wire import (Cursor, application, control_frame, frame, hello, nwsc_accept, nwsc_probe, parse_nwsc_feedback,
                      nwsc_feedback, nwsc_start, parse_application, parse_hello,
                      parse_setup, setup_message, string)
from ids_wire import plain_setup_reply
from pairing_session import encode_tlvs, tlvs
from resources import save_resource


async def read_control(reader, limit=65535):
    prefix = await reader.readexactly(2)
    size = int.from_bytes(prefix, 'big')
    if not 1 <= size <= limit:
        raise ValueError('Invalid length-prefixed IDS frame')
    return prefix + await reader.readexactly(size)


class IdsSession:
    def __init__(self, normal, store, record, timeout=60, listen_only=False, allow_wake_recovery=False):
        self.listen_only = listen_only
        self.allow_wake_recovery = allow_wake_recovery
        self.wake_recovery_started = False
        self.control_policy_rejected = False
        self.normal, self.store, self.record, self.timeout = normal, store, record, timeout
        self.control = None
        self.lanes, self.setups, self.servers, self.tasks = {}, {}, [], set()
        self.incoming = asyncio.Queue(maxsize=256)
        self.peer_hello = None
        self.hello_ready = asyncio.Event()
        self.lane_ready = {lane: asyncio.Event() for lane in ('d', 'c')}
        self.lane_joined = {lane: asyncio.Event() for lane in ('d', 'c')}
        self.maps, self.outgoing_maps = {}, {}
        self.inline_topic_counts = {}
        self.sequence = 0
        self.connector_sequence = time.time_ns() // 1000 - time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 2000
        self.closed = False
        self.error = None
        self.phase = 'not_started'
        self.write_locks = {}
        self.nwsc_keys = {}
        self.nwsc_slot_keys = {}  # (lane, listener port) -> (sequence, key): normal and Cloud connectors publish different keys
        self.connecting_services = set()
        self.transports = {}
        self.handshakes = set()
        self.pending_nwsc = {}
        self.active_nwsc = {}
        self.setup_events = {}
        self.key_probe_locks = {lane: asyncio.Lock() for lane in ('d', 'c')}
        self.incoming_control_candidates = set()
        self.incoming_control_decided = asyncio.Event()
        self.incoming_control_decided.set()
        if normal is not None:
            normal.on_error = self.fail
            if normal.error:
                self.fail(normal.error)

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def fail(self, error):
        if self.error is None and not self.closed:
            self.error = error
            trace = error.__traceback__
            while trace and trace.tb_next:
                trace = trace.tb_next
            self.record('ids_failed', error=type(error).__name__,
                        error_function=trace.tb_frame.f_code.co_name if trace else '',
                        error_line=trace.tb_lineno if trace else 0)
            self.hello_ready.set()
            for ready in self.lane_ready.values():
                ready.set()
            for joined in self.lane_joined.values():
                joined.set()
            if not self.incoming.full():
                self.incoming.put_nowait(error)

    async def wait_ready(self, ready):
        if self.error:
            raise self.error
        await asyncio.wait_for(ready.wait(), self.timeout)
        if self.error:
            raise self.error

    async def write(self, writer, data):
        if self.error:
            raise self.error
        lock = self.write_locks.setdefault(writer, asyncio.Lock())
        async with lock:
            if self.error:
                raise self.error
            writer.write(data)
            await writer.drain()

    async def wait_transport_quiet(self, minimum_wait=0):
        """Runtime pacing: wait for queued/unacknowledged TCP before setup."""
        started = asyncio.get_running_loop().time()
        while True:
            if self.error:
                raise self.error
            writers = set(self.transports.values())
            if self.control is not None:
                writers.add(self.control)
            queued = 0
            for writer in writers:
                sock = writer.get_extra_info('socket')
                if sock is None:
                    raise RuntimeError('Cannot inspect IDS TCP send queue')
                # Linux TIOCOUTQ includes unsent and unacknowledged bytes.
                queued += struct.unpack('i', fcntl.ioctl(sock.fileno(), termios.TIOCOUTQ,
                                                       struct.pack('i', 0)))[0]
                queued += writer.transport.get_write_buffer_size()
            outstanding = int(self.normal.link.ertm.pending is not None)
            elapsed = asyncio.get_running_loop().time() - started
            if queued == 0 and outstanding <= 1 and elapsed >= minimum_wait:
                self.record('ids_transport_quiet', tcp_pending=0, ertm_pending=outstanding)
                return
            if elapsed >= self.timeout:
                raise TimeoutError('IDS transport did not become quiet for setup')
            await asyncio.sleep(0.01)

    async def connect(self, lane, port):
        """Keep the SYN source listening for the Watch's reverse key probe."""
        session = self.normal.sessions[lane]
        address = str(ipaddress.IPv6Address(session.local_address))
        server = await asyncio.start_server(
            lambda r, w: self.spawn(self.accept_connection(lane, r, w, port)), address, 0, reuse_port=True)
        self.servers.append(server)
        source_port = server.sockets[0].getsockname()[1]
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setblocking(False)
        try:
            sock.bind((address, source_port))
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock,
                (str(ipaddress.IPv6Address(session.remote_address)), port)), self.timeout)
            return await asyncio.open_connection(sock=sock)
        except BaseException:
            sock.close()
            raise

    def observe_nwsc_feedback(self, lane, reply, port=None):
        flags, sequence, key = parse_nwsc_feedback(reply)
        if port is not None:
            previous = self.nwsc_slot_keys.get((lane, port))
            if previous is None or sequence >= previous[0]:
                self.nwsc_slot_keys[(lane, port)] = (sequence, key)
        previous = self.nwsc_keys.get(lane)
        if previous is None or sequence >= previous[0]:
            self.nwsc_keys[lane] = (sequence, key)
        return flags

    async def discover_nwsc_key(self, lane, port):
        self.record('nwsc_key_probe_started', lane=lane, port=port)
        reader, writer = await self.connect(lane, port)
        try:
            self.connector_sequence += 1
            await self.write(writer, nwsc_probe(port,
                self.connector_sequence, self.store.sign(lane)))
            self.observe_nwsc_feedback(lane, await asyncio.wait_for(read_control(reader, 346), self.timeout), port)
            self.record('nwsc_key_probe_completed', lane=lane)
        finally:
            writer.close()
            await writer.wait_closed()

    async def open(self, lane, port, service):
        endpoint = (lane, service)
        if endpoint in self.pending_nwsc:
            raise ValueError('NWSC service connection already pending')
        attempt = {'uuid': uuid.uuid4().bytes, 'retry': asyncio.Event(), 'task': asyncio.current_task(), 'port': port}
        self.pending_nwsc[endpoint] = attempt
        try:
            for retry_count in range(3):
                attempt['retry'].clear()
                self.record('ids_tcp_connect_started', lane=lane, port=port)
                reader, writer = await self.connect(lane, port)
                keep = False
                retry_wait = asyncio.create_task(attempt['retry'].wait())
                feedback_wait = None
                try:
                    self.record('ids_tcp_connected', lane=lane, port=port)
                    if service == 'ids-control-channel':
                        if self.control is not None:
                            raise asyncio.CancelledError('Incoming control claimed the service')
                        if self.incoming_control_candidates:
                            self.record('ids_outgoing_control_deferred', lane=lane)
                            await asyncio.wait_for(self.incoming_control_decided.wait(), self.timeout)
                        if self.control is not None:
                            raise asyncio.CancelledError('Incoming control claimed the service')
                    self.connector_sequence += 1
                    attempt['sequence'] = self.connector_sequence
                    source_port = writer.get_extra_info('sockname')[1]
                    attempt['source_port'] = source_port
                    attempt['sent'] = True
                    signed_port = source_port if retry_count else port
                    await self.write(writer, nwsc_start(signed_port, self.connector_sequence, service,
                        self.store.sign(lane), attempt['uuid']))
                    self.phase = 'waiting_nwsc_feedback'
                    self.record('nwsc_request_sent', lane=lane, port=signed_port, service=service)
                    deadline = asyncio.get_running_loop().time() + self.timeout
                    while True:
                        feedback_wait = asyncio.create_task(read_control(reader, 346))
                        done, _ = await asyncio.wait((feedback_wait, retry_wait),
                            timeout=max(0, deadline - asyncio.get_running_loop().time()),
                            return_when=asyncio.FIRST_COMPLETED)
                        if not done:
                            raise TimeoutError('NWSC service feedback timed out')
                        if retry_wait in done:
                            self.record('nwsc_retry_requested', lane=lane, service=service)
                            break
                        reply = feedback_wait.result()
                        flags = self.observe_nwsc_feedback(lane, reply, port)
                        self.record('nwsc_feedback_received', lane=lane, flags=flags, service=service)
                        if flags == 0:
                            continue
                        if flags != 0x80:
                            raise ValueError('Watch rejected NWSC service')
                        self.record('nwsc_accepted', lane=lane, service=service)
                        self.active_nwsc[endpoint] = (attempt['sequence'], attempt['uuid'], writer)
                        keep = True
                        return reader, writer
                finally:
                    waits = [task for task in (feedback_wait, retry_wait) if task is not None]
                    for task in waits:
                        task.cancel()
                    await asyncio.gather(*waits, return_exceptions=True)
                    if not keep:
                        writer.close()
                        await writer.wait_closed()
            raise TimeoutError('NWSC Retry limit reached')
        finally:
            self.pending_nwsc.pop(endpoint, None)

    async def wake_class_d(self):
        """Paired-wake: open the Urgent-D lane instead of control, so the Watch opens control itself."""
        name = 'UTunDelivery-Default-Urgent-D'
        if name in self.setups or name in self.transports or name in self.connecting_services:
            return
        self.connecting_services.add(name)
        service = 'idstest/localdelivery/' + name
        self.record('ids_class_d_wake_started')
        try:
            reader, writer = await self.open('d', 61314, service)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            # 0x40 or silence is an expected answer here; keep waiting for the Watch's control.
            self.connecting_services.discard(name)
            self.record('ids_class_d_wake_failed', error=type(error).__name__)
            if isinstance(error, ValueError) and str(error) == 'Watch rejected NWSC service':
                await self.recover_rejected_wake()
            return
        try:
            if name not in self.setups:
                # An admitted wake transport can arrive without control Setup.
                # Do not install this placeholder while admission is pending:
                # it would suppress the reply to a real Watch Setup.
                self.setups[name] = {'guid': str(uuid.uuid4()), 'local_port': 0,
                    'remote_port': 61314, 'name': name, 'established': True, 'await_incoming': True}
            await self.attach('d', service, reader, writer)
        finally:
            self.connecting_services.discard(name)

    async def recover_rejected_wake(self):
        if (not self.allow_wake_recovery or self.wake_recovery_started or self.peer_hello is not None
                or self.control is not None or self.control_policy_rejected or self.closed):
            return
        self.wake_recovery_started = True
        self.phase = 'probing_rejected_wake_keys'
        self.record('ids_wake_recovery_started')
        try:
            for lane in ('d', 'c'):
                for port in (61314, 61315):
                    if self.peer_hello is not None or self.control is not None or self.closed:
                        return
                    async with self.key_probe_locks[lane]:
                        await self.discover_nwsc_key(lane, port)
            self.record('ids_wake_recovery_probes_completed')
            await self.open_control(recovery=True)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.phase = 'waiting_incoming_control'
            self.record('ids_wake_recovery_failed', error=type(error).__name__)

    async def open_control(self, recovery=False):
        writer = None
        if (self.listen_only and not recovery) or self.control_policy_rejected:
            # A paired bootstrap never SYNs ids-control, and a 0x40
            # rejection must not be followed by another control SYN.
            self.phase = 'waiting_incoming_control'
            self.record('ids_outgoing_control_skipped', listen_only=self.listen_only,
                        policy_rejected=self.control_policy_rejected)
            return
        try:
            reader, writer = await self.open('d', 61315, 'ids-control-channel')
            if self.control is None and not self.closed:
                self.control = writer
                await self.write(writer, hello(self.store.data['ids_id'], uuid.uuid4()))
                self.spawn(self.read_control_loop(reader, writer))
            else:
                writer.close()
                await writer.wait_closed()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if writer is not None and self.control is writer:
                self.fail(error)
            else:
                if isinstance(error, ValueError) and 'rejected' in str(error):
                    self.control_policy_rejected = True
                # The Watch may initiate its own control connection instead.
                self.phase = 'waiting_incoming_control'
                self.record('ids_outgoing_control_failed', error=type(error).__name__)
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    async def start(self):
        if self.error:
            raise self.error
        self.phase = 'starting_listeners'
        for lane in ('d', 'c'):
            address = str(ipaddress.IPv6Address(self.normal.sessions[lane].local_address))
            for port in (61314, 61315):
                server = await asyncio.start_server(lambda r, w, lane=lane, port=port: self.spawn(self.accept_connection(lane, r, w, port)),
                                                    address, port)
                self.servers.append(server)
                self.record('ids_listener_ready', lane=lane, port=port)
        if self.listen_only:
            # Observed live: Urgent-D goes out in the same burst as LinkDirector, before its ACK; waiting
            # until after the ACK (0.2.298) leaves the service unclaimed and ends in 0x40 after 20 s.
            self.spawn(self.wake_class_d())
            await asyncio.sleep(0)
        await self.normal.announce()
        self.phase = 'waiting_control_hello'
        self.record('ids_waiting_for_control_hello')
        outgoing = self.spawn(self.open_control())
        try:
            await self.wait_ready(self.hello_ready)
        finally:
            outgoing.cancel()
            await asyncio.gather(outgoing, return_exceptions=True)
        for lane in ('d', 'c'):
            self.phase = 'opening_lane_' + lane
            name = 'UTunDelivery-Default-Urgent-' + lane.upper()
            if name in self.setups:
                await self.wait_ready(self.lane_joined[lane])
                continue
            state = {'guid': str(uuid.uuid4()), 'local_port': secrets.randbelow(40000) + 15000,
                     'remote_port': 61314, 'name': name, 'key': secrets.token_bytes(60),
                     'ssrc': secrets.randbits(32), 'seq': secrets.randbits(16), 'established': False}
            self.setups[name] = state
            # The setup port is independent from NWSC's listening ports.
            server = await asyncio.start_server(lambda r, w, lane=lane: self.spawn(self.accept_connection(lane, r, w, 61314)),
                str(ipaddress.IPv6Address(self.normal.sessions[lane].local_address)), state['local_port'])
            self.servers.append(server)
            await self.write(self.control, setup_message(state['local_port'], state['remote_port'], state['guid'], None,
                name, state['key'], state['ssrc'], state['seq']))
            await self.wait_ready(self.lane_joined[lane])
        for lane in ('d', 'c'):
            await self.wait_ready(self.lane_ready[lane])
        self.record('ids_lanes_ready')
        self.phase = 'ready'

    async def accept_connection(self, lane, reader, writer, connector_port=None):
        control_candidate = False
        probe = False
        try:
            request = await asyncio.wait_for(read_control(reader, 346), self.timeout)
            while len(request) == 81 and request[:2] == b'\0\x4f' and request[12:16] == bytes(4) and request[80] in (0, 1):
                probe = True
                self.connector_sequence += 1
                feedback = nwsc_feedback(self.connector_sequence, self.store.sign(lane).public_key().public_bytes_raw())
                await self.write(writer, feedback[:2] + bytes(2) + feedback[4:])
                self.record('nwsc_key_probe_responded', lane=lane, operation=request[80])
                if request[80] == 1:
                    local_port = writer.get_extra_info('sockname')[1]
                    for (pending_lane, _), attempt in list(self.pending_nwsc.items()):
                        if pending_lane == lane and (attempt.get('source_port') == local_port
                                or attempt['port'] == connector_port):
                            attempt['retry'].set()
                # Keep this stream until the Watch closes it.
                # It can carry another operation after the initial response.
                try:
                    request = await asyncio.wait_for(read_control(reader, 346), self.timeout)
                except asyncio.IncompleteReadError as error:
                    if error.partial:
                        raise ValueError('Truncated NWSC probe') from error
                    return
            probe = False
            if (len(request) < 94 or len(request) != 93 + request[28]
                    or not request[28] or not int.from_bytes(request[2:4], 'big')):
                raise ValueError('Malformed NWSC service request')
            self.record('nwsc_request_verifying', lane=lane, length=len(request))
            if request[29:-64] == b'ids-control-channel':
                self.incoming_control_candidates.add(writer)
                self.incoming_control_decided.clear()
            connector_port = connector_port or (61315 if request[29:-64] == b'ids-control-channel' else 61314)
            async with self.key_probe_locks[lane]:
                slot = (lane, connector_port)
                fresh = False
                if slot not in self.nwsc_slot_keys and lane not in self.nwsc_keys:
                    await self.discover_nwsc_key(lane, connector_port)
                    fresh = True
                key = self.nwsc_slot_keys.get(slot) or self.nwsc_keys[lane]
                try:
                    service, sequence = nwsc_accept(request, key[1])
                except InvalidSignature:
                    if fresh:
                        self.record('nwsc_signature_mismatch', lane=lane, port=connector_port, fresh=True,
                                    service=request[29:-64].decode('latin1')[:80])
                        raise
                    # The Watch signs normal and Cloud requests with different connector keys: re-probe this listener once.
                    await self.discover_nwsc_key(lane, connector_port)
                    key = self.nwsc_slot_keys.get(slot) or self.nwsc_keys[lane]
                    try:
                        service, sequence = nwsc_accept(request, key[1])
                    except InvalidSignature:
                        self.record('nwsc_signature_mismatch', lane=lane, port=connector_port, fresh=True,
                                    service=request[29:-64].decode('latin1')[:80])
                        raise
            self.record('nwsc_request_received', lane=lane, length=len(request), service=service,
                        local_port=self.socket_tag(writer), peer_port=self.socket_tag(writer, 'peername'))
            control_candidate = service == 'ids-control-channel'
            valid = not self.closed and ((control_candidate and (self.control is None
                or (lane, service) in self.active_nwsc)) or service.startswith('idstest/localdelivery/UTunDelivery-Default-'))
            if service != 'ids-control-channel':
                name = service.split('/')[-1]
                valid = valid and (name.endswith('-' + lane.upper()) or lane == 'd' and name.endswith('-D-Relay'))
            pending = self.pending_nwsc.get((lane, service))
            transient = valid and pending is not None and pending.get('sent', False) and pending['uuid'] > request[12:28]
            active = self.active_nwsc.get((lane, service))
            if active is not None and (sequence, request[12:28]) <= active[:2]:
                transient = True
            if transient:
                valid = False
            elif valid and pending is not None:
                pending['task'].cancel()
                self.record('nwsc_incoming_won_collision', lane=lane, service=service)
            if valid and control_candidate:
                # Claim ownership before NWSC feedback yields to another candidate.
                if self.control is not None:
                    self.peer_hello = None
                    self.hello_ready.clear()
                self.control = writer
            if valid:
                self.active_nwsc[(lane, service)] = (sequence, request[12:28], writer)
                if active is not None:
                    active[2].close()
            self.connector_sequence += 1
            feedback = nwsc_feedback(self.connector_sequence, self.store.sign(lane).public_key().public_bytes_raw(), valid)
            if transient:
                feedback = feedback[:2] + bytes(2) + feedback[4:]
            await self.write(writer, feedback)
            if not valid:
                self.record('nwsc_route_rejected', lane=lane, service=service)
                return
            if service == 'ids-control-channel':
                await self.write(writer, hello(self.store.data['ids_id'], uuid.uuid4()))
                await self.read_control_loop(reader, writer)
            else:
                await self.attach(lane, service, reader, writer, incoming=True)
        except asyncio.CancelledError:
            raise
        except InvalidSignature:
            self.connector_sequence += 1
            feedback = nwsc_feedback(self.connector_sequence, self.store.sign(lane).public_key().public_bytes_raw())
            await self.write(writer, feedback[:2] + bytes(2) + feedback[4:])
            self.record('nwsc_signature_rejected', lane=lane)
        except Exception as error:
            if probe:
                self.record('nwsc_probe_closed', lane=lane, error=type(error).__name__)
            elif not control_candidate or self.control is None or self.control is writer:
                self.fail(error)
        finally:
            self.incoming_control_candidates.discard(writer)
            if not self.incoming_control_candidates:
                self.incoming_control_decided.set()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def read_service_frame(self, reader, control=False):
        # Late NWSC Feedback is dropped before dispatching an active
        # service. It has a different header from IDS data frames.
        while True:
            prefix = await reader.readexactly(2)
            if prefix == b'\x00\x2a':
                feedback = prefix + await reader.readexactly(42)
                self.record('nwsc_late_feedback_ignored', flags=feedback[2], length=44)
                continue
            if control:
                size = int.from_bytes(prefix, 'big')
                if not 1 <= size <= 65535:
                    raise ValueError('Invalid length-prefixed IDS frame')
                body = await reader.readexactly(size)
                return body[0], body
            prefix += await reader.readexactly(3)
            size = int.from_bytes(prefix[1:], 'big')
            if size > LIMIT - 5:
                raise ValueError('IDS socket frame exceeds limit')
            return prefix[0], await reader.readexactly(size)

    async def read_control_loop(self, reader, writer=None):
        try:
            while True:
                _, body = await self.read_service_frame(reader, control=True)
                if self.peer_hello is None and body[0] != 1:
                    self.record('ids_control_before_hello', type=body[0], length=len(body))
                if body[0] == 1:
                    if self.peer_hello is not None:
                        raise ValueError('Repeated IDS Hello')
                    self.peer_hello = parse_hello(body)
                    peer_id = self.store.peer_notifies().get(0xbddf)
                    if peer_id and uuid.UUID(peer_id.decode()) != self.peer_hello['device']:
                        raise ValueError('IDS Hello identity differs from PIN-enrolled Watch')
                    # Runtime enables basic direct messaging: announce our own
                    # version 1 with zero feature mask, never echo peer info.
                    if writer is not None or self.control is not None:
                        await self.write(writer if writer is not None else self.control,
                                         control_frame(b'\x0e\x01' + bytes(15)))
                        self.record('ids_direct_message_info_sent', version=1)
                    self.hello_ready.set()
                    self.record('ids_hello_received', pairing_version=self.peer_hello['maximum'])
                elif body[0] in (2, 6, 13):
                    await self.accept_setup(parse_setup(body))
                else:
                    self.record('ids_control_received', type=body[0], length=len(body))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if writer is None or self.control is writer:
                self.fail(error)

    async def accept_setup(self, incoming):
        name = incoming['name']
        lane = 'c' if name.endswith('-C') else 'd' if name.endswith('-D') or name.endswith('-D-Relay') else None
        if lane is None or not name.startswith('UTunDelivery-Default-'):
            self.record('ids_setup_ignored', type=incoming['kind'])
            return
        state = self.setups.get(name)
        if incoming['peer_guid']:
            if state is None or uuid.UUID(incoming['peer_guid']) != uuid.UUID(state['guid']):
                return  # stale reply for another runtime connection
            if incoming['kind'] == 6 and (incoming['remote_port'] != state['local_port']
                    or incoming['local_port'] != state['remote_port']):
                raise ValueError('IDS Setup reply ports are not reciprocal')
            if state['established']:
                return
        if incoming['kind'] in (2, 13):
            if state is None:
                state = {'guid': str(uuid.uuid4()), 'local_port': incoming['local_port'],
                         'remote_port': incoming['remote_port'], 'name': name, 'established': False}
                self.setups[name] = state
            if not incoming['peer_guid'] and not state['established']:
                state['await_incoming'] = True
                await self.write(self.control, plain_setup_reply(incoming, state['guid']))
                self.record('ids_setup_replied', lane=lane, type=incoming['kind'])
            state['established'] = True
            self.setup_events.setdefault(name, asyncio.Event()).set()
            self.record('ids_setup_established', lane=lane, type=incoming['kind'])
            return
        if state is None:
            state = {'guid': str(uuid.uuid4()), 'local_port': incoming['remote_port'],
                     'remote_port': incoming['local_port'], 'name': name, 'key': secrets.token_bytes(60),
                     'ssrc': secrets.randbits(32), 'seq': secrets.randbits(16), 'established': False}
            self.setups[name] = state
            address = str(ipaddress.IPv6Address(self.normal.sessions[lane].local_address))
            if state['local_port'] not in (61314, 61315):
                server = await asyncio.start_server(lambda r, w: self.spawn(self.accept_connection(lane, r, w, 61314)),
                                                    address, state['local_port'])
                self.servers.append(server)
            await self.write(self.control, setup_message(state['local_port'], state['remote_port'], state['guid'], incoming['guid'],
                name, state['key'], state['ssrc'], state['seq']))
        elif not incoming['peer_guid'] and not state['established'] and uuid.UUID(state['guid']).hex > uuid.UUID(incoming['guid']).hex:
            state['local_port'], state['remote_port'] = incoming['remote_port'], incoming['local_port']
        if state['established']:
            return
        state['established'] = True
        self.setup_events.setdefault(name, asyncio.Event()).set()
        self.record('ids_setup_established', lane=lane, type=incoming['kind'])
        if name not in self.transports and name not in self.connecting_services and not state.get('await_incoming'):
            service = 'idstest/localdelivery/' + name
            self.connecting_services.add(name)
            self.spawn(self.open_lane(lane, service))

    async def open_lane(self, lane, service):
        try:
            reader, writer = await self.open(lane, 61314, service)
            await self.attach(lane, service, reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if service.split('/')[-1] not in self.transports:
                self.fail(error)
        finally:
            self.connecting_services.discard(service.split('/')[-1])

    async def fail_if_transport_missing(self, name, error, grace=20):
        await asyncio.sleep(grace)
        if name not in self.transports and not self.closed:
            self.fail(error)

    async def attach(self, lane, service, reader, writer, incoming=False):
        name = service.split('/')[-1]
        try:
            state = self.setups.get(name)
            if state is None or not state['established']:
                await asyncio.wait_for(self.setup_events.setdefault(name, asyncio.Event()).wait(), self.timeout)
            previous = self.transports.get(name)
            if previous is not None and previous is not writer:
                previous.close()
            self.transports[name] = writer
            self.record('ids_transport_attached', lane=lane, service=name, incoming=incoming,
                        local_port=self.socket_tag(writer))
            if name == 'UTunDelivery-Default-Urgent-' + lane.upper():
                self.lane_joined[lane].set()
                self.record('ids_data_service_joined', lane=lane)
            if incoming:
                await self.write(writer, frame(4, struct.pack('>I', 1)))
                self.handshakes.add(writer)
            fragments, maps = {}, {}
            ready = False
            while True:
                command, body = await self.read_service_frame(reader)
                size = len(body)
                if command == 21:
                    if size < 12:
                        raise ValueError('Short IDS fragment')
                    identifier, index, count = struct.unpack_from('>III', body)
                    if not 1 <= count <= 132 or index >= count or size > 7995:
                        raise ValueError('Invalid IDS fragment metadata')
                    if identifier not in fragments and len(fragments) >= 16:
                        raise ValueError('Too many incomplete IDS messages')
                    slot = fragments.setdefault(identifier, {'count': count, 'parts': {}})
                    if slot['count'] != count or index in slot['parts'] and slot['parts'][index] != body[12:]:
                        raise ValueError('Conflicting IDS fragment')
                    slot['parts'][index] = body[12:]
                    if sum(map(len, slot['parts'].values())) > LIMIT:
                        raise ValueError('IDS reassembly exceeds limit')
                    if len(slot['parts']) < count:
                        continue
                    assembled = b''.join(slot['parts'][n] for n in range(count))
                    del fragments[identifier]
                    if len(assembled) < 5 or int.from_bytes(assembled[1:5], 'big') != len(assembled) - 5 or assembled[0] == 21:
                        raise ValueError('Invalid reassembled IDS frame')
                    command, body = assembled[0], assembled[5:]
                await self.accept_frame(lane, writer, command, body, maps)
                if command == 4 and not ready:
                    ready = True
                    self.record('ids_socket_handshake_received', lane=lane)
                    if name == 'UTunDelivery-Default-Urgent-' + lane.upper():
                        self.lanes[lane] = writer
                        self.lane_ready[lane].set()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if self.transports.get(name) is writer:
                if name in ('UTunDelivery-Default-Urgent-' + lane.upper(), 'UTunDelivery-Default-Default-' + lane.upper()):
                    if isinstance(error, (asyncio.IncompleteReadError, ConnectionError)) and not self.closed:
                        # The Watch closes our outgoing socket when its own request for the same service wins
                        # the collision; give its replacement connection time to arrive before failing.
                        self.record('ids_transport_lost', lane=lane, service=name, error=type(error).__name__)
                        self.spawn(self.fail_if_transport_missing(name, error))
                    else:
                        self.fail(error)
                else:
                    # Cloud/Sync sockets are retried by the Watch; their reset must not end the session.
                    self.record('ids_aux_transport_closed', lane=lane, service=name, error=type(error).__name__)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            if self.transports.get(name) is writer:
                self.transports.pop(name, None)

    @staticmethod
    def socket_tag(writer, which='sockname'):
        getter = getattr(writer, 'get_extra_info', None)
        name = getter(which) if getter else None
        return name[1] if name else None

    async def accept_frame(self, lane, writer, command, body, maps):
        if command in (1, 37):
            if len(body) != 4:
                raise ValueError('Malformed IDS acknowledgement')
            await self.incoming.put({'event': 'ack', 'sequence': int.from_bytes(body, 'big'), 'lane': lane})
            self.record('ids_transport_ack_received', lane=lane, command=command,
                        sequence=int.from_bytes(body, 'big'))
        elif command == 7:
            c = Cursor(body)
            seq, stream, peer = c.number(4), c.number(2), c.string()
            has_topic = c.offset < len(body)
            topic = c.string() if has_topic else self.maps.get(stream)
            c.end()
            if has_topic:
                self.learn_peer_stream(stream, topic)
                self.local_stream_for(topic)
            await self.incoming.put({'event': 'app_ack', 'peer': peer, 'topic': topic, 'lane': lane})
        elif command == 39:
            fields = tlvs(body)
            if len(fields.get(2, b'')) != 2 or not fields.get(3):
                raise ValueError('Malformed IDS ServiceMap')
            stream, topic = int.from_bytes(fields[2], 'big'), fields[3].decode()
            if fields.get(1) != b'\x01':
                raise ValueError('Unsupported IDS ServiceMap reason')
            self.learn_peer_stream(stream, topic)
        elif command in (0, 3, 6, 22):
            # Inline topics describe the peer's receive mapping, not ours.
            message = parse_application(command, body, dict(self.maps))
            if message['flags'] & 16:
                self.learn_peer_stream(message['stream'], message['topic'])
                local_stream = self.local_stream_for(message['topic'])
                topic = message['topic']
                count = self.inline_topic_counts.get(topic, 0) + 1
                self.inline_topic_counts[topic] = count
                if count == 3:
                    await self.write(writer, frame(39, encode_tlvs({1: b'\x01',
                        2: local_stream.to_bytes(2, 'big'), 3: topic.encode()})))
                    self.record('ids_service_map_sent', stream=local_stream, topic=topic)
            message.update(event='message', lane=lane)
            self.record('ids_message_received_socket', lane=lane, local_port=self.socket_tag(writer),
                        lane_port=self.socket_tag(self.lanes[lane]) if lane in self.lanes else None,
                        sequence=message['sequence'], command=command, flags=message.get('flags'),
                        has_peer=bool(message.get('peer')), stream=message.get('stream'))
            if command == 22:
                received, total = save_resource(self.store, message['id'], message['payload'])
                self.record('ids_resource_saved', received=received, total=total, complete=received == total)
                if received != total:
                    return
            await self.write(writer, frame(1, struct.pack('>I', message['sequence'])))
            self.record('ids_transport_ack_sent', lane=lane, sequence=message['sequence'])
            # AppAck records validated delivery; setup progress is evaluated separately.
            if message['flags'] & 4:
                stream = self.stream_for(message['topic'])
                seq = self.allocate()
                await self.write(writer, frame(7, struct.pack('>IH', seq, stream) + string(message['id']) + string(message['topic'])))
            if command != 22:
                await self.incoming.put(message)
        elif command == 4:
            if len(body) != 4:
                raise ValueError('Malformed IDS socket handshake')
            self.record('ids_peer_handshake', lane=lane, version=int.from_bytes(body, 'big'), local_port=self.socket_tag(writer))
            if writer not in self.handshakes:
                await self.write(writer, frame(4, struct.pack('>I', 1)))
                self.handshakes.add(writer)
        elif command == 2:
            if body:
                raise ValueError('Malformed IDS keepalive')
        else:
            self.record('ids_command_unhandled', command=command, length=len(body))

    def allocate(self):
        if self.sequence > 0xffffffff:
            raise ValueError('IDS sequence exhausted')
        seq, self.sequence = self.sequence, self.sequence + 1
        return seq

    def learn_peer_stream(self, stream, topic):
        if not 1 <= stream <= 65535 or not topic:
            raise ValueError('Invalid IDS peer stream mapping')
        previous = self.outgoing_maps.get(stream)
        if previous is not None and previous != topic or any(
                name == topic and identifier != stream for identifier, name in self.outgoing_maps.items()):
            raise ValueError('Conflicting IDS peer stream mapping')
        self.outgoing_maps[stream] = topic
        self.record('ids_peer_stream_learned', stream=stream, topic=topic)

    def stream_for(self, topic):
        for stream, name in self.outgoing_maps.items():
            if topic == name:
                return stream
        return self.local_stream_for(topic)

    def local_stream_for(self, topic):
        for stream, name in self.maps.items():
            if topic == name:
                return stream
        stream = len(self.maps) + 1
        if stream > 65535:
            raise ValueError('IDS stream IDs exhausted')
        self.maps[stream] = topic
        return stream

    async def send(self, topic, kind, payload=b'', flags=0, peer='', response=False, command=None, expiry=None):
        if self.error:
            raise self.error
        lane = 'd' if topic in CLASS_D_TOPICS else 'c'
        writer = self.lanes[lane]
        # Observed on a Watch SE 3: frames are acknowledged only when sent on the Default-priority sockets.
        writer = self.transports.get(f'UTunDelivery-Default-Default-{lane.upper()}', writer)
        seq, identifier, stream = self.allocate(), str(uuid.uuid4()).upper(), self.stream_for(topic)
        include_topic = topic not in self.outgoing_maps.values()
        wire = application(seq, stream, topic, identifier, payload, kind, flags, peer, response,
                           include_topic=include_topic, command=command, expiry=expiry)
        if len(wire) > 8000:
            message_id = secrets.randbits(32)
            slices = [wire[n:n + 7983] for n in range(0, len(wire), 7983)]
            for n, part in enumerate(slices):
                await self.write(writer, frame(21, struct.pack('>III', message_id, n, len(slices)) + part))
        else:
            await self.write(writer, wire)
        self.record('ids_message_sent', topic=topic, lane=lane, command=wire[0], wire_flags=wire[11], wire_stream=int.from_bytes(wire[9:11], 'big'),
                    local_port=self.socket_tag(writer),
                    type=kind, sequence=seq, length=len(payload))
        return {'sequence': seq, 'id': identifier, 'topic': topic}

    async def receive(self):
        if self.error:
            raise self.error
        result = await asyncio.wait_for(self.incoming.get(), self.timeout)
        if self.error:
            raise self.error
        if isinstance(result, Exception):
            raise result
        return result

    async def close(self):
        self.closed = True
        for server in self.servers:
            server.close()
        writers = set(self.lanes.values()) | set(self.transports.values())
        if self.control:
            writers.add(self.control)
        for writer in writers:
            writer.close()
        pending = list(self.tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for writer in writers:
            await writer.wait_closed()
        for server in self.servers:
            await server.wait_closed()
