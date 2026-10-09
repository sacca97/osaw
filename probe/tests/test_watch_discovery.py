"""Offline discovery: actual BLE reports, setup metadata and user selection."""
import asyncio
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bumble.device import Advertisement, AdvertisementDataAccumulator
from bumble.hci import Address, HCI_LE_Advertising_Report_Event, HCI_LE_Extended_Advertising_Report_Event
from bumble.smp import AddressResolver
import watch_poc


async def check():
    address = Address('C2:02:03:04:05:06')
    setup = bytes.fromhex('208837d4ce64385000d01000')
    data = bytes([16, 22]) + b'\x25\xfe\x06' + setup
    accumulator = AdvertisementDataAccumulator()
    report = HCI_LE_Advertising_Report_Event.Report
    assert accumulator.update(report(0, 1, address, b'\x02\x01\x1a', -40)) is None
    combined = accumulator.update(report(4, 1, address, data, -39))
    candidate = watch_poc.watch_candidate(combined)
    assert candidate == {'address': address, 'rssi': -39, 'product': 'Watch7,5', 'setup': setup}
    extended = HCI_LE_Extended_Advertising_Report_Event.Report
    accumulator = AdvertisementDataAccumulator()
    def extended_report(event_type, payload, rssi):
        return extended(event_type=event_type, address_type=1, address=address,
            primary_phy=1, secondary_phy=0, advertising_sid=255, tx_power=127, rssi=rssi,
            periodic_advertising_interval=0, direct_address_type=0,
            direct_address=Address.ANY, data=payload)
    assert accumulator.update(extended_report(0x13, b'\x02\x01\x1a', -40)) is None
    combined = accumulator.update(extended_report(0x1b, data, -39))
    assert watch_poc.watch_candidate(combined) == candidate
    assert watch_poc.watch_candidate(Advertisement(address, data_bytes=data)) is None
    assert watch_poc.watch_candidate(Advertisement(address, is_connectable=True,
           data_bytes=b'\x05\x16\x25\xfe\x06\x20')) is None
    assert watch_poc.setup_payload(b'\x25\xfe\x86\x0c' + setup + b'ignored') == setup
    assert watch_poc.setup_payload(b'\x0f\x18\x06' + setup) is None

    def no_prompt(_):
        raise AssertionError('Single candidate must be selected automatically')
    assert await watch_poc.select_watch([candidate], no_prompt) is candidate
    other = dict(candidate, address=Address('C2:02:03:04:05:07'))
    answers = iter(['0', 'abc', '3', '2'])
    assert await watch_poc.select_watch([candidate, other], lambda _: next(answers)) is other
    try:
        await watch_poc.select_watch([])
    except ValueError:
        pass
    else:
        raise AssertionError('Empty scan must not select a Watch')

    # A bond identifies the same Watch after its over-the-air address rotates.
    irk = bytes(range(16))
    resolver = AddressResolver([(irk, address)])
    assert resolver.can_resolve_to(address)
    assert resolver.resolve(Address.generate_private_address(irk)) == address


with redirect_stdout(io.StringIO()):
    asyncio.run(check())
    async def default_run(args):
        assert not args.scan and not args.peer and not args.setup_data
    with patch.object(sys, 'argv', ['watch_poc.py']), patch.object(sys, 'platform', 'linux'), \
            patch.object(watch_poc, 'run', default_run):
        assert watch_poc.main() == 0
print('Watch discovery, automatic/numbered selection and rotating identity checks passed')
