"""Companion network relay: forwards the Watch's per-daemon TCP flows to the internet.

Captured companion relay traffic opens a TCP connection to the phone's terminus
address and prefixes the stream with a small header naming the target and the
originating service:

    u16 header_length        (bytes following this field)
    u8  version (=1)
    u16 destination_port     (e.g. 0x01bb = 443)
    u8  hostname_length
    ... hostname             (SNI-equivalent, e.g. "gsa.apple.com")
    u8  type (=3)
    u16 service_length
    ... service_name         (originating daemon, e.g. "com.apple.mobileassetd")
    ... relayed bytes        (the TLS ClientHello and everything after)

This prototype connects to host:port, sends back the captured 8-byte flow-open
acknowledgment, and splices both directions. Whether advertising this
prototype resolves the observed MobileAsset Download 65 errors is unverified.

Only envelope metadata is logged (target host, port, service name); relayed bytes
are never recorded.
"""
import asyncio
import ipaddress
import re

PROXY_PORT = 62742
FLOW_OPEN = bytes.fromhex('0006000004000120')
HOST_RE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
SERVICE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')


def parse_relay_header(buffer):
    """Return (host, port, service, remaining_bytes) or None if not a relay header."""
    if len(buffer) < 7:
        return None
    header_length = int.from_bytes(buffer[0:2], 'big')
    if not 3 <= header_length <= 2048:
        return None
    version = buffer[2]
    port = int.from_bytes(buffer[3:5], 'big')
    host_length = buffer[5]
    host_end = 6 + host_length
    if version != 1 or not 1 <= port <= 65535 or len(buffer) < host_end + 3:
        return None
    host = buffer[6:host_end]
    kind = buffer[host_end]
    service_length = int.from_bytes(buffer[host_end + 1:host_end + 3], 'big')
    service_end = host_end + 3 + service_length
    if kind != 3 or not 1 <= service_length <= 512 or len(buffer) < service_end:
        return None
    if header_length != service_end - 2:
        return None
    try:
        host_string, service_string = host.decode('ascii'), buffer[host_end + 3:service_end].decode('ascii')
    except UnicodeDecodeError:
        return None
    if not HOST_RE.fullmatch(host_string) or not SERVICE_RE.fullmatch(service_string):
        return None
    return host_string, port, service_string, buffer[service_end:]


class RelayProxy:
    def __init__(self, record, addresses, port=PROXY_PORT, connect_timeout=20.0):
        self.record = record
        self.addresses = [str(ipaddress.IPv6Address(address)) for address in addresses]
        self.port = port
        self.connect_timeout = connect_timeout
        self.servers = []
        self.bound_addresses = []
        self.tasks = set()
        self.closed = False

    async def start(self):
        for address in self.addresses:
            try:
                server = await asyncio.start_server(self.handle, address, self.port)
            except OSError as error:
                self.record('relay_proxy_listen_failed', address=address, port=self.port,
                            error=type(error).__name__)
                continue
            self.servers.append(server)
            self.bound_addresses.append(address)
            self.record('relay_proxy_listening', address=address, port=self.port)

    async def close(self):
        self.closed = True
        for server in self.servers:
            server.close()
        for server in self.servers:
            try:
                await server.wait_closed()
            except Exception:
                pass
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.servers = []
        self.bound_addresses = []

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream_writer = None
        pumps = []
        phase = 'header'
        metadata = {}
        counts = {'watch_to_upstream': 0, 'upstream_to_watch': 0}
        try:
            if self.closed:
                return
            prefix = await asyncio.wait_for(reader.readexactly(2), self.connect_timeout)
            header_length = int.from_bytes(prefix, 'big')
            if not 3 <= header_length <= 2048:
                raise ValueError('invalid relay header length')
            body = await asyncio.wait_for(reader.readexactly(header_length), self.connect_timeout)
            parsed = parse_relay_header(prefix + body)
            if parsed is None:
                raise ValueError('invalid relay header')
            host, port, service, pending = parsed
            metadata = dict(host=host, port=port, service=service)
            self.record('relay_proxy_flow', host=host, port=port, service=service)
            phase = 'connect'
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.connect_timeout)
            self.record('relay_proxy_connected', host=host, port=port, service=service)
            phase = 'relay'
            writer.write(FLOW_OPEN)
            await writer.drain()
            if pending:
                upstream_writer.write(pending)
                await upstream_writer.drain()
            pumps = [asyncio.create_task(self.pump(reader, upstream_writer, counts, 'watch_to_upstream', metadata)),
                     asyncio.create_task(self.pump(upstream_reader, writer, counts, 'upstream_to_watch', metadata))]
            sent, received = await asyncio.gather(*pumps)
            self.record('relay_proxy_flow_complete', host=host, port=port, service=service,
                        bytes_to_upstream=sent + len(pending), bytes_to_watch=received)
        except Exception as error:
            self.record('relay_proxy_flow_failed', phase=phase,
                        error=type(error).__name__, errno=getattr(error, 'errno', None),
                        bytes_from_watch=counts['watch_to_upstream'],
                        bytes_from_upstream=counts['upstream_to_watch'], **metadata)
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            writers = [writer] + ([upstream_writer] if upstream_writer is not None else [])
            for stream in writers:
                stream.close()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(stream.wait_closed() for stream in writers), return_exceptions=True), 5)
            except TimeoutError:
                pass
            finally:
                self.tasks.discard(task)

    async def pump(self, reader, writer, counts, direction, metadata):
        total = 0
        while True:
            data = await reader.read(65536)
            if not data:
                # Half-close only the outgoing direction; the response may still arrive.
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return total
            if total == 0:
                tls = len(data) >= 3 and 20 <= data[0] <= 24 and data[1] == 3
                self.record('relay_proxy_first_data', direction=direction, length=len(data),
                            prefix_format='tls_record' if tls else 'other', **metadata)
            counts[direction] += len(data)
            writer.write(data)
            await writer.drain()
            total += len(data)
