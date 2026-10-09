"""Apple dynamic CID transport: bounded ERTM and ordered NRLP stream.

Unsegmented SDUs are enough: NRLP and IKE can split their own messages.
One outstanding frame keeps window/retransmission behavior deterministic.
"""
import asyncio
import struct
import time
from nrlp import Stream, build_inner_message


class Ertm:
    def __init__(self, connection, tx_cid, record, timeout=30):
        self.connection, self.tx_cid, self.record = connection, tx_cid, record
        self.timeout, self.tx_seq, self.rx_seq = timeout, 0, 0
        # ponytail: one SDU per ACK; widen the window only if live throughput blocks setup.
        self.pending = None
        self.ready = asyncio.Event()
        self.ready.set()
        self.incoming = asyncio.Queue(maxsize=256)
        self.lock = asyncio.Lock()
        self.error = None
        self.remote_busy = False

    def raw_send(self, control, payload=b''):
        self.connection.send_l2cap_pdu(self.tx_cid, struct.pack('<H', control) + payload)

    def rr(self, final=False, poll=False):
        self.raw_send(1 | (self.rx_seq << 8) | (0x80 if final else 0) | (0x10 if poll else 0))

    def feed(self, packet):
        try:
            if len(packet) < 2:
                raise ValueError('Short ERTM frame')
            control = struct.unpack_from('<H', packet)[0]
            ack = (control >> 8) & 63
            if self.pending is not None:
                seq, data = self.pending
                if ack == (seq + 1) % 64:
                    self.pending = None
                    self.ready.set()
                elif ack != seq:
                    raise ValueError('ERTM acknowledgement exceeds transmit window')
            elif ack != self.tx_seq:
                raise ValueError('Unexpected ERTM acknowledgement')
            if control & 1:
                if len(packet) != 2 or control & 0xc062:
                    raise ValueError('Malformed ERTM supervisory frame')
                function = (control >> 2) & 3
                self.remote_busy = function == 2
                if function in (1, 3) and self.pending:
                    seq, data = self.pending
                    self.raw_send((seq << 1) | (self.rx_seq << 8), data)
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
            self.ready.set()
            if not self.incoming.full():
                self.incoming.put_nowait(error)

    async def wait_ack(self):
        deadline = time.monotonic() + self.timeout
        while not self.ready.is_set() or self.remote_busy:
            if self.error:
                raise self.error
            if time.monotonic() >= deadline:
                raise TimeoutError('ERTM receiver did not acknowledge frame')
            try:
                await asyncio.wait_for(self.ready.wait(), 1)
            except TimeoutError:
                if self.pending and not self.remote_busy:
                    seq, previous = self.pending
                    self.raw_send((seq << 1) | (self.rx_seq << 8), previous)
                self.rr(poll=True)
            if self.remote_busy:
                self.rr(poll=True)
                await asyncio.sleep(.1)
        if self.error:
            raise self.error

    async def send(self, data):
        async with self.lock:
            await self.wait_ack()
            seq = self.tx_seq
            self.tx_seq = (seq + 1) % 64
            self.pending = seq, bytes(data)
            self.ready.clear()
            self.raw_send((seq << 1) | (self.rx_seq << 8), data)
            await self.wait_ack()

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
            await self.messages.put(error)

    async def send_message(self, kind, payload):
        wire = build_inner_message(payload, kind)
        # NRLP is one byte stream: another sender must not splice a message
        # between ERTM chunks of this one.
        async with self.send_lock:
            for offset in range(0, len(wire), 1000):
                await self.ertm.send(wire[offset:offset + 1000])

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
