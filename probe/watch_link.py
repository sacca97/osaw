"""Apple dynamic CID transport: bounded ERTM and ordered NRLP stream.

Unsegmented SDUs are enough: NRLP and IKE can split their own messages.
Pairing uses one outstanding frame; normal links can pipeline a bounded window.
"""
import asyncio
import struct
import time
from collections import OrderedDict, deque
from nrlp import Stream, build_inner_message


class Ertm:
    def __init__(self, connection, tx_cid, record, timeout=30, window=1, mps=1000):
        if not 1 <= window <= 32 or not 1 <= mps <= 2042:
            raise ValueError('Unsupported ERTM window or MPS')
        self.connection, self.tx_cid, self.record = connection, tx_cid, record
        self.timeout, self.tx_seq, self.rx_seq = timeout, 0, 0
        self.window, self.mps = window, mps
        self.unacknowledged = deque()
        self.history = OrderedDict()
        self.timer = None
        self.closed = False
        self.last_progress = time.monotonic()
        self.tx_frames = self.tx_acknowledged = self.tx_retransmissions = 0
        self.ready = asyncio.Event()
        self.ready.set()
        self.incoming = asyncio.Queue(maxsize=256)
        self.lock = asyncio.Lock()
        self.error = None
        self.remote_busy = False

    @property
    def pending(self):
        return self.unacknowledged[0] if self.unacknowledged else None

    def retransmit(self, frames):
        for seq, data in frames:
            self.raw_send((seq << 1) | (self.rx_seq << 8), data)
            self.tx_retransmissions += 1

    def raw_send(self, control, payload=b''):
        self.connection.send_l2cap_pdu(self.tx_cid, struct.pack('<H', control) + payload)

    def rr(self, final=False, poll=False):
        self.raw_send(1 | (self.rx_seq << 8) | (0x80 if final else 0) | (0x10 if poll else 0))

    def feed(self, packet):
        if self.closed:
            return
        try:
            if len(packet) < 2:
                raise ValueError('Short ERTM frame')
            control = struct.unpack_from('<H', packet)[0]
            ack = (control >> 8) & 63
            base = self.pending[0] if self.pending else self.tx_seq
            distance = (ack - base) % 64
            if distance <= len(self.unacknowledged):
                for _ in range(distance):
                    seq, data = self.unacknowledged.popleft()
                    self.history.pop(seq, None)
                    self.history[seq] = data
                    while len(self.history) > 32:
                        self.history.popitem(last=False)
                if distance:
                    self.tx_acknowledged += distance
                    self.last_progress = time.monotonic()
            elif self.window == 1 or not 0 < (base - ack) % 64 <= 32:
                raise ValueError('ERTM acknowledgement exceeds transmit window')
            # A delayed supervisory ACK behind the current window is stale.
            self.ready.set()
            if control & 1:
                if len(packet) != 2 or control & 0xc062:
                    raise ValueError('Malformed ERTM supervisory frame')
                function = (control >> 2) & 3
                self.remote_busy = function == 2
                if function == 1:
                    self.retransmit(tuple(self.unacknowledged))
                elif function == 3:
                    data = next((data for seq, data in self.unacknowledged if seq == ack),
                                self.history.get(ack))
                    if data is not None:
                        self.retransmit(((ack, data),))
                if control & 0x10:
                    self.rr(final=True)
                return
            if control >> 14:
                raise ValueError('Segmented ERTM SDU is unsupported by this profile')
            seq = (control >> 1) & 63
            if seq == self.rx_seq:
                self.incoming.put_nowait(packet[2:])
                self.rx_seq = (self.rx_seq + 1) % 64
                self.rr()
            elif (self.rx_seq - seq) % 64 < 32:
                self.rr()  # duplicate retransmission; never redeliver
            else:
                self.raw_send(1 | (1 << 2) | (self.rx_seq << 8))
        except Exception as error:
            self.fail(error)

    def fail(self, error):
        if self.error is None:
            self.error = error
            if self.timer and self.timer is not asyncio.current_task():
                self.timer.cancel()
            self.ready.set()
            if not self.incoming.full():
                self.incoming.put_nowait(error)

    async def retransmission_timer(self):
        try:
            while self.unacknowledged:
                await asyncio.sleep(1)
                if not self.unacknowledged:
                    return
                elapsed = time.monotonic() - self.last_progress
                if elapsed >= self.timeout:
                    raise TimeoutError('ERTM receiver did not acknowledge frame')
                if elapsed >= 1:
                    if not self.remote_busy:
                        self.retransmit(tuple(self.unacknowledged))
                    self.rr(poll=True)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fail(error)

    async def wait_available(self, drain=False):
        deadline = time.monotonic() + self.timeout
        while self.remote_busy or (bool(self.unacknowledged) if drain else len(self.unacknowledged) >= self.window):
            if self.closed:
                raise ConnectionError('ERTM channel is closed')
            if self.error:
                raise self.error
            if time.monotonic() >= deadline:
                raise TimeoutError('ERTM receiver did not acknowledge frame')
            self.ready.clear()
            try:
                await asyncio.wait_for(self.ready.wait(), 1)
            except TimeoutError:
                if self.remote_busy:
                    self.rr(poll=True)
        if self.error:
            raise self.error

    async def wait_ack(self):
        await self.wait_available(drain=True)

    async def send(self, data):
        if self.closed:
            raise ConnectionError('ERTM channel is closed')
        if len(data) > self.mps:
            raise ValueError('ERTM payload exceeds MPS')
        async with self.lock:
            await self.wait_available()
            seq = self.tx_seq
            self.tx_seq = (seq + 1) % 64
            if not self.unacknowledged:
                self.last_progress = time.monotonic()
            self.unacknowledged.append((seq, bytes(data)))
            self.raw_send((seq << 1) | (self.rx_seq << 8), data)
            self.tx_frames += 1
            if self.timer is None or self.timer.done():
                self.timer = asyncio.create_task(self.retransmission_timer())
            if self.window == 1:
                await self.wait_ack()

    async def close(self):
        self.closed = True
        self.ready.set()
        if self.timer:
            self.timer.cancel()
            await asyncio.gather(self.timer, return_exceptions=True)

    async def receive(self):
        if self.error:
            raise self.error
        result = await self.incoming.get()
        if isinstance(result, Exception):
            raise result
        return result


class RelayLink:
    def __init__(self, ertm, record, timeout=30):
        self.ertm, self.record, self.timeout = ertm, record, timeout
        self.stream = Stream()
        self.messages = asyncio.Queue(maxsize=256)
        self.on_message = None
        self.on_error = None
        self.deferred = []
        self.send_lock = asyncio.Lock()
        self.task = asyncio.create_task(self.read_loop())

    async def read_loop(self):
        try:
            while True:
                data = await self.ertm.receive()
                for kind, payload in self.stream.feed(data):
                    if not self.on_message or not await self.on_message(kind, payload):
                        await self.messages.put((kind, payload))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.ertm.fail(error)
            if self.on_error:
                self.on_error(error)
            await self.messages.put(error)

    async def send_message(self, kind, payload):
        wire = build_inner_message(payload, kind)
        # NRLP is one byte stream: another sender must not splice a message
        # between ERTM chunks of this one.
        async with self.send_lock:
            mps = getattr(self.ertm, 'mps', 1000)
            for offset in range(0, len(wire), mps):
                await self.ertm.send(wire[offset:offset + mps])

    async def send(self, packet):
        await self.send_message(4, packet)

    async def request(self, packets, accept):
        # IKE retries reuse exact ciphertext and IV, ERTM retries exact SDUs.
        for attempt in range(3):
            for packet in packets:
                await self.send(packet)
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self.messages.get(), remaining)
                except TimeoutError:
                    break
                if isinstance(item, Exception):
                    raise item
                kind, wire = item
                if kind != 4:
                    if len(self.deferred) >= 256:
                        raise ValueError('Deferred NRLP queue exceeds limit')
                    self.deferred.append((kind, wire))
                    continue
                result = accept(wire)
                if result is not None:
                    return result
            self.record('ike_request_retry', attempt=attempt + 1)
        raise TimeoutError('Watch did not complete the IKE exchange')

    async def close(self):
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        if close := getattr(self.ertm, 'close', None):
            await close()
