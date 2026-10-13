"""Initial NanoRegistry, activation and native PairedSync setup state machine."""
import base64
import hashlib
from pathlib import Path
import plistlib
import re
import time
from pairing_store import user_owned
import uuid
import yaml
from Crypto.Util.asn1 import DerSequence, DerOctetString
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from apple_codec import (APPSYNC, CREDS, TIMESYNC, NANO_C, NANO_D, PBB, PREFS, PSY,
    timesync_clock_replies, timesync_message_type, timesync_state_replies, apple_time,
    archive, bplist, decode_nr_properties, field, nr_properties, one, preferences, protobuf, sync_state)


def service_diagnostics(payload, depth=0):
    """Envelope/error metadata only; no raw bodies, descriptions or credentials."""
    try:
        value = plistlib.loads(payload)
    except Exception:
        try:
            fields = protobuf(payload)
            return {'payload_format': 'protobuf',
                    'field_summary': {str(tag): {'count': len(items),
                                                'numbers': [v for v in items[:8] if type(v) in (int, bool)],
                                                'byte_lengths': [len(v) for v in items[:8] if isinstance(v, bytes)]}
                                      for tag, items in list(fields.items())[:32]}}
        except Exception:
            return {'payload_format': 'opaque'}
    if not isinstance(value, dict):
        return {'payload_format': 'plist', 'root_type': type(value).__name__}
    keys = sorted(k for k in value if isinstance(k, str) and
                  re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_.$-]{0,95}', k))[:64]
    summary = {'payload_format': 'plist', 'keys': keys,
               'field_types': {key: type(value[key]).__name__ for key in keys},
               'numeric_fields': {key: value[key] for key in keys
                                  if key in ('T', 'E', 'EO', 'command', 'type', 'operation', 'messageType',
                                             'errorCode', 'error-code', 'code', 'status', 'success')
                                  and type(value[key]) in (int, bool)}}
    if isinstance(value.get('MessageType'), str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,63}', value['MessageType']):
        summary['message_type'] = value['MessageType']
    if isinstance(value.get('BI'), str) and re.fullmatch(r'com\.apple\.[A-Za-z0-9_.-]{1,100}', value['BI']):
        summary['bundle_id'] = value['BI']
    if isinstance(value.get('ED'), str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', value['ED']):
        summary['error_domain'] = value['ED']
    if 'EM' in value:
        summary['error_description_type'] = type(value['EM']).__name__
        if isinstance(value['EM'], (str, bytes)):
            summary['error_description_length'] = len(value['EM'])
    if isinstance(value.get('EO'), bytes):
        summary['error_object_length'] = len(value['EO'])
        if depth < 2 and len(value['EO']) <= 65536:
            summary['error_details'] = service_diagnostics(value['EO'], depth + 1)
    # OTA ScanResult carries an archived SUBDescriptor and/or NSError under these keys.
    if 'Descriptor' in value:
        summary['descriptor_present'] = True
        summary['descriptor_type'] = type(value['Descriptor']).__name__
        if isinstance(value['Descriptor'], (bytes, str, list, dict)):
            summary['descriptor_length'] = len(value['Descriptor'])
    if isinstance(value.get('Error'), bytes):
        summary['error_field_length'] = len(value['Error'])
        if depth < 2 and len(value['Error']) <= 65536:
            summary['error_field_details'] = service_diagnostics(value['Error'], depth + 1)
    summary['collection_counts'] = {key: len(value[key]) for key in ('BL', 'IL', 'RA')
                                    if isinstance(value.get(key), (list, dict))}
    if type(value.get('RS')) in (int, bool):
        summary['numeric_fields']['RS'] = value['RS']
    # NSKeyedArchiver errors store codes/domains in $objects, sometimes through UIDs.
    objects = value.get('$objects')
    if isinstance(objects, list):
        errors = []
        for obj in objects[:256]:
            if not isinstance(obj, dict) or type(obj.get('NSCode')) is not int:
                continue
            error = {'code': obj['NSCode']}
            domain = obj.get('NSDomain')
            if isinstance(domain, plistlib.UID) and domain.data < len(objects):
                domain = objects[domain.data]
            if isinstance(domain, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,127}', domain):
                error['domain'] = domain
                if domain == 'com.apple.MobileAssetError.Download':
                    # Watch23T240 MobileAsset _stringForMADownloadResult table.
                    name = {47: 'MADownloadNetworkingError',
                            53: 'MADownloadTimedOutResource',
                            65: 'MADownloadNotConnectedToInternet'}.get(obj['NSCode'])
                    if name:
                        error['result_name'] = name
            if domain == 'SUBError' and obj['NSCode'] == 34:
                # Watch23T240 nanosubridged error builder at 0x1000356ac.
                error['reason'] = 'Update requires companion update'
            errors.append(error)
            if len(errors) == 8:
                break
        summary['archived_errors'] = errors
    return summary



def public_identity(signing, encryption):
    point = signing.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    public_rsa = encryption.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return DerSequence([DerOctetString(len(point).to_bytes(2, 'big') + point, implicit=1).encode(),
                        DerOctetString(len(public_rsa).to_bytes(2, 'big') + public_rsa, implicit=2).encode()]).encode()


def validate_identity(encoded):
    if not 80 <= len(encoded) <= 4096:
        raise ValueError('Invalid IDS public identity length')
    sequence = DerSequence().decode(encoded, strict=True, nr_elements=2)
    values = []
    for tag, item in zip((1, 2), sequence):
        value = DerOctetString(implicit=tag).decode(item, strict=True).payload
        if len(value) < 2 or int.from_bytes(value[:2], 'big') != len(value) - 2:
            raise ValueError('Invalid IDS key length prefix')
        values.append(value[2:])
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), values[0])
    public = serialization.load_der_public_key(values[1])
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 1280 or public.public_numbers().e != 65537:
        raise ValueError('Unexpected IDS RSA identity profile')
    return encoded


def local_identities(store):
    saved = store.data.get('ids_message_private')
    if saved is None:
        saved = {}
        for lane in ('A', 'C', 'D'):
            signing, encryption = ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 1280)
            saved[lane] = [key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).hex() for key in (signing, encryption)]
        store.save(ids_message_private=saved)
    result = {}
    for lane, values in saved.items():
        keys = [serialization.load_der_private_key(bytes.fromhex(value), None) for value in values]
        result[lane] = validate_identity(public_identity(*keys))
    return result


def phone_properties(store):
    """The companion phone's NanoRegistry properties, replayed from a real iPhone's own snapshot
    (phone_profile.yaml); identifiers are ours or absent."""
    profile = yaml.safe_load(Path(__file__).with_name('phone_profile.yaml').read_text())
    values = dict.fromkeys(profile['property_names'])
    values.update(profile['values'])
    values.update(bluetoothMACAddress=store.key('host_address'), deviceNameString='iPhone',
                  capabilities={uuid.UUID(value) for value in profile['capabilities']})
    return values


# Default Watch apps the iPhone announces on the app-sync conduit (message type 30) in a real pairing; the Watch
# installs them automatically. Public Apple bundle identifiers only.
DEFAULT_WATCH_APPS = [
    'com.apple.NanoHome', 'com.apple.NanoNotes', 'com.apple.NanoBooks', 'com.apple.NanoMail', 'com.apple.VoiceMemos',
    'com.apple.podcasts', 'com.apple.NanoMusic', 'com.apple.NanoWorldClock', 'com.apple.ActivityMonitorApp',
    'com.apple.weather.watchapp', 'com.apple.NanoCamera', 'com.apple.NanoCalendar', 'com.apple.MobileSMS',
    'com.apple.NanoReminders', 'com.apple.shortcuts.watch', 'com.apple.AppStore', 'com.apple.NanoPhotos',
    'com.apple.NanoPassbook', 'com.apple.tincan', 'com.apple.NanoCompass.watchkitapp', 'com.apple.stocks.watchapp',
    'com.apple.NanoMaps', 'com.apple.NanoCalculator.watchkitapp', 'com.apple.nanonews', 'com.apple.NanoContacts']


def failure_summary(payload):
    """Field numbers, integers and short printable strings of an activation-failure body; no long or binary values."""
    def short(value):
        if isinstance(value, bytes):
            try:
                value = value.decode()
            except UnicodeDecodeError:
                return f'<{len(value)} bytes>'
        if isinstance(value, str):
            return value if len(value) <= 120 and value.isprintable() else f'<{len(value)} chars>'
        return value
    try:
        if payload[:8] == b'bplist00' or payload[:5] == b'<?xml':
            data = plistlib.loads(payload)
            return {str(k): short(v) for k, v in data.items()} if isinstance(data, dict) else type(data).__name__
        return {str(k): [short(v) for v in values][:4] for k, values in protobuf(payload).items()}
    except Exception as error:
        return f'undecodable: {type(error).__name__}'


class SetupFlow:
    def __init__(self, ids, store, record, proxy, product, language='en-US', locale='en_US', timezone='UTC'):
        self.ids, self.store, self.record, self.proxy = ids, store, record, proxy
        self.product, self.language, self.locale, self.timezone = product, language, locale, timezone
        self.public = local_identities(store)
        self.request_id = str(uuid.uuid4()).upper()
        self.peer_info = False
        # A Watch that already holds our identities does not
        # ask again on reconnect, so delivery counts as done until it sends a new command 11.
        self.local_info_ack = bool(store.data.get('ids_device_info_exchanged'))
        self.local_info_sequences = set()
        self.peer_info_requests = set()
        self.watch = {}
        self.check = self.snapshot = self.property_request = self.normal = self.prepare = self.completion = None
        self.configured = self.activation = self.language_done = self.is_setup = self.sync_complete = False
        self.sync_values, self.sync_timestamps = {}, {}
        self.normal_sent = self.completion_ack = False
        self.seen_messages = set()
        self.app_sync_sent = False
        self.activation_cache = {}
        self.phone = phone_properties(store)
        self.reconnecting = store.data.get('setup_complete', False)

    def pairing_mode(self, state):
        version = self.ids.peer_hello['maximum'] or 26
        return field(1, state) + field(2, 26) + field(3, version) + field(4, 25)

    def diagnostic_status(self):
        values = {'watch_is_setup': self.is_setup, 'watch_setup_present': 'isSetup' in self.watch,
                'activation': self.activation,
                'sync_complete': self.sync_complete, 'completion_ack': self.completion_ack,
                'watch_sync_progress': self.sync_values.get('PSYWatchSyncState', {}).get('syncProgressState'),
                'watch_global_progress': self.sync_values.get('PSYWatchSyncState', {}).get('globalProgress'),
                'client_sync_progress': self.sync_values.get('PSYWatchSyncClientState', {}).get('syncProgressState')}
        return {key: value if type(value) in (bool, int, float) else None
                for key, value in values.items()}


    async def run(self):
        await self.ids.wait_transport_quiet()
        await self.ids.send(CREDS, None, bplist({'command': 11, 'unique-id': self.request_id}))
        while True:
            await self.accept(await self.ids.receive())
            await self.advance()
            if self.reconnecting and self.peer_info and self.local_info_ack and self.is_setup:
                self.record('reconnected_to_initialized_watch', is_setup=True)
                return
            if self.activation and self.is_setup and self.sync_complete and self.completion_ack:
                self.store.save(stage='setup_protocol_complete', paired=True, setup_complete=True)
                self.record('setup_protocol_complete', activation=True, is_setup=True, paired_sync=True,
                            physical_app_usability_verified=False)
                return

    async def accept(self, message):
        if message['event'] == 'ack':
            sequence = message['sequence']
            if sequence in self.local_info_sequences and message['lane'] == 'd':
                self.local_info_sequences.discard(sequence)
                self.local_info_ack = True
                self.record('ids_local_device_info_acknowledged')
            if self.check and sequence == self.check['sequence'] and message['lane'] == 'd' and not self.snapshot:
                self.snapshot = await self.ids.send(NANO_C, 2, nr_properties(self.phone, born_on=apple_time()))
            if self.snapshot and sequence == self.snapshot['sequence'] and message['lane'] == 'c' and not self.property_request:
                self.property_request = await self.ids.send(NANO_C, 4, flags=1)
            return
        if message['event'] == 'app_ack':
            if self.completion and message['topic'] == self.completion['topic'] and message['peer'].upper() == self.completion['id']:
                self.completion_ack = True
                self.record('paired_sync_application_receipt')
            return
        topic, kind, payload = message['topic'], message['type'], message['payload']
        self.record('setup_message_received', topic=topic, type=kind, length=len(payload))
        key = (topic, message['id'])
        # Resource chunks intentionally reuse one UUID and are stored separately by IDS.
        if key in self.seen_messages and topic not in (PBB, CREDS):
            return
        if len(self.seen_messages) >= 8192:
            raise ValueError('Setup message history exceeds limit')
        self.seen_messages.add(key)
        if topic == CREDS:
            await self.device_info(message)
        elif topic == TIMESYNC:
            await self.timesync(message)
        elif topic == APPSYNC:
            await self.app_sync(message)
        elif topic == 'com.apple.private.alloy.otaupdate':
            self.record('ota_message_received', type=kind, length=len(payload),
                        response=bool(message.get('response')),
                        response_expected=bool(message['flags'] & 1),
                        has_peer=bool(message.get('peer')),
                        message_fingerprint=hashlib.sha256(message['id'].upper().encode()).hexdigest()[:16],
                        peer_fingerprint=hashlib.sha256(message['peer'].upper().encode()).hexdigest()[:16]
                                         if message.get('peer') else None,
                        application_handler='not_implemented', **service_diagnostics(payload))
        elif topic in (NANO_C, NANO_D):
            if kind == 4 and not message['response']:
                await self.ids.send(topic, 4, nr_properties(self.phone, response=True), peer=message['id'], response=True)
            elif kind == 2 or kind == 4 and message['response']:
                received = decode_nr_properties(payload, response=kind == 4)
                self.watch.update(received)
                self.is_setup = self.watch.get('isSetup') is True
                if self.is_setup:
                    self.record('watch_is_setup_observed')
                if 'productType' in self.watch and self.watch['productType'] != self.product:
                    raise ValueError('Watch NanoRegistry product differs from its setup advertisement')
            elif kind == 3 and message['response']:
                if self.normal and message['peer'].upper() == self.normal['id'] and one(protobuf(payload), 1) != 1:
                    raise ValueError('Watch rejected Normal pairing mode')
        elif topic == PBB:
            await self.pbbridge(message)
        elif topic in (PSY, PREFS) and kind in (0, 2):
            fields = protobuf(payload)
            domain = one(fields, 2, b'').decode()
            if domain == 'com.apple.pairedsync':
                timestamp = one(fields, 1, 0) if kind == 0 else 0.0
                for key in fields.get(3, []):
                    item = protobuf(key)
                    name = one(item, 1, b'').decode()
                    value = one(item, 2)
                    if name not in ('PSYWatchSyncState', 'PSYWatchSyncClientState') or value is None:
                        continue
                    changed = one(item, 4, timestamp)
                    if not isinstance(changed, (int, float)) or isinstance(changed, bool):
                        raise ValueError('Invalid PairedSync timestamp')
                    if changed >= self.sync_timestamps.get(name, float('-inf')):
                        decoded = plistlib.loads(value)
                        if not isinstance(decoded, dict) or type(decoded.get('version')) is not int or decoded['version'] != 1:
                            raise ValueError('Invalid Watch PairedSync state')
                        self.sync_values[name], self.sync_timestamps[name] = decoded, changed
                self.update_sync_complete()

    def update_sync_complete(self):
        watch = self.sync_values.get('PSYWatchSyncState', {})
        client = self.sync_values.get('PSYWatchSyncClientState', {})
        self.sync_complete = (self.completion is not None and watch.get('syncProgressState') == 3
                              and watch.get('globalProgress') == 100 and client.get('syncProgressState') == 3)
        if self.sync_complete:
            self.record('watch_paired_sync_complete_observed')

    async def app_sync(self, message):
        """Announce the default app list once the Watch speaks on the conduit, as the iPhone does after setup:
        type 30 with the bundle list, then type 34, both Dictionary messages with expiry and a response expected."""
        try:  # message types and key names only; the lists inside may name the owner's own apps
            decoded = plistlib.loads(message['payload'])
            self.record('app_sync_message', message_type=decoded.get('T'), keys=sorted(decoded),
                        response_expected=bool(message['flags'] & 1), correlated=bool(message['peer']))
        except Exception:
            self.record('app_sync_message', message_type=None, keys=[], response_expected=bool(message['flags'] & 1))
        self.record('app_sync_diagnostic', length=len(message['payload']),
                    response=bool(message.get('response')),
                    response_expected=bool(message['flags'] & 1),
                    has_peer=bool(message.get('peer')),
                    message_fingerprint=hashlib.sha256(message['id'].upper().encode()).hexdigest()[:16],
                    peer_fingerprint=hashlib.sha256(message['peer'].upper().encode()).hexdigest()[:16]
                                     if message.get('peer') else None,
                    **service_diagnostics(message['payload']))
        if self.app_sync_sent:
            return
        self.app_sync_sent = True
        expiry = int(apple_time()) + 3600
        await self.ids.send(APPSYNC, None, bplist({'T': 30, 'BL': DEFAULT_WATCH_APPS}), flags=9, command=6, expiry=expiry)
        await self.ids.send(APPSYNC, None, bplist({'T': 34}), flags=9, command=6, expiry=expiry)
        self.record('app_sync_default_apps_sent', apps=len(DEFAULT_WATCH_APPS))

    async def timesync(self, message):
        kind = timesync_message_type(message['payload'])
        self.record('timesync_received', message_type=kind, expects_response=bool(message['flags'] & 1))
        now, monotonic = time.time(), time.monotonic()
        if kind == 6:
            replies = timesync_state_replies(self.timezone)
        elif kind == 8:
            values = plistlib.loads(message['payload'])
            self.record('timesync_clock_sample',
                        remote_mach=values.get('kTMLSLinkRemoteMachKey'),
                        remote_rtc=values.get('kTMLSLinkRTCKey'),
                        uncertainty=values.get('kTMLSLinkUncertaintyKey'),
                        host_unix=now, host_monotonic=monotonic, timezone=self.timezone)
            replies = timesync_clock_replies(message['payload'], now, monotonic)
        else:
            return
        for reply in replies:
            await self.ids.send(TIMESYNC, None, reply)
        self.record('timesync_answered', message_type=kind, replies=len(replies),
                    host_unix=now, host_monotonic=monotonic, timezone=self.timezone,
                    time_source='TMLSSourceComputed' if kind == 8 else None)

    async def account_request(self, values):
        """Local IDS account RPCs: this companion has no Apple Account, so fetch gets empty accounts and sync is refused.
        An invalid request gets no reply and does not end setup."""
        try:
            correlation = values.get('unique-id')
            if not isinstance(correlation, str) or len(correlation) != 36 or str(uuid.UUID(correlation)).upper() != correlation.upper():
                raise ValueError('correlation')
            reply = {'unique-id': correlation}
            if values['command'] == 17:
                services = values.get('serviceTypes')
                if not isinstance(services, list) or len(services) > 64 or not all(
                        isinstance(name, str) and len(name) <= 255 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name)
                        for name in services):
                    raise ValueError('service list')
                reply.update(command=18, accountMap={name: [] for name in services})
                event = ('ids_account_fetch_answered', {'services': len(services), 'accounts': 0})
            else:
                if not isinstance(values.get('sync-payload'), dict):
                    raise ValueError('sync payload')
                operation = values['sync-payload'].get('command')
                # Operation 5 (SPS companion info) is acknowledged as the iPhone does; anything else is unsupported.
                reply.update(command=16, success=operation == 5)
                event = ('ids_account_sync_acknowledged' if operation == 5 else 'ids_account_sync_refused', {'operation': operation})
        except ValueError as error:
            self.record('ids_credential_command_unsupported', command=values['command'], reason=str(error))
            return
        await self.ids.send(CREDS, None, bplist(reply))
        self.record(event[0], **event[1])

    async def device_info(self, message):
        values = plistlib.loads(message['payload'])
        if not isinstance(values, dict):
            raise ValueError('IDS credential request must be a dictionary')
        if values.get('command') in (15, 17):
            await self.account_request(values)
            return
        if values.get('command') not in (11, 12):
            command = values.get('command')
            self.record('ids_credential_command_unsupported', command=command if type(command) is int else None)
            return
        unique = values.get('unique-id', '')
        uuid.UUID(unique)
        self.record('ids_device_info_received', command=values['command'],
                    correlated=unique.upper() == self.request_id)
        if values['command'] == 11:
            normalized = str(uuid.UUID(unique)).upper()
            if normalized not in self.peer_info_requests and len(self.peer_info_requests) >= 16:
                raise ValueError('Too many IDS device-info requests')
            if len(self.local_info_sequences) >= 32:
                raise ValueError('Too many pending IDS device-info replies')
            self.peer_info_requests.add(normalized)
            self.local_info_ack = False
            identifier = self.store.data['ids_id'].upper()
            private = {'v': '1', 'pn': 'iPhone OS', 'pv': '26.6', 'pb': '23G71', 'u': identifier,
                       **{key: '1' for key in ('ap', 'h', 't', 's', 'm', 'p', 'c')}, 'ec': '8'}
            reply = {'command': 12, 'unique-id': unique, 'identifier': identifier, 'success': True,
                     'encryption-key': self.public['D'], 'encryption-class-a-key': self.public['A'],
                     'encryption-class-c-key': self.public['C'], 'private-device-data': private,
                     'device-name': 'iPhone', 'hardware-version': 'iPhone18,1'}
            sent = await self.ids.send(CREDS, None, bplist(reply))
            self.local_info_sequences.add(sent['sequence'])
            self.record('ids_device_info_reply_sent', sequence=sent['sequence'])
        elif unique.upper() == self.request_id:
            if values.get('success') is not True or uuid.UUID(values['identifier']) != self.ids.peer_hello['device']:
                raise ValueError('Watch IDS device-info identity mismatch')
            peer_keys = {}
            for label, name in (('A', 'encryption-class-a-key'), ('C', 'encryption-class-c-key'), ('D', 'encryption-key')):
                key = values[name]
                if isinstance(key, str):
                    key = base64.b64decode(key, validate=True)
                validate_identity(key)
                if key in self.public.values():
                    raise ValueError('Watch reflected a local IDS identity')
                peer_keys[label] = key.hex()
            self.store.save(ids_peer_public=peer_keys)
            self.peer_info = True
            self.record('ids_device_info_verified')

    async def pbbridge(self, message):
        kind, payload = message['type'], message['payload']
        if kind == 2:
            encoded = one(protobuf(payload), 1)
            if not isinstance(encoded, bytes):
                raise ValueError('Watch activation request is missing')
            key = message['id']
            if key in self.activation_cache:
                previous, response = self.activation_cache[key]
                if previous != encoded:
                    raise ValueError('Activation request changed during retry')
            else:
                if len(self.activation_cache) >= 8:
                    raise ValueError('Too many activation requests in one setup attempt')
                response = await self.proxy.relay(encoded)
                self.activation_cache[key] = encoded, response
            await self.ids.send(PBB, 2, response, peer=key)
        elif kind == 4:
            self.activation = True
            self.store.save(stage='activation_confirmed', activation_confirmed=True)
            self.record('watch_activation_confirmed')
        elif kind == 12:
            # Keep the possibly identifying body out of the event log; save it privately and log only its shape.
            path = self.store.directory / 'activation-failure.bin'
            path.write_bytes(payload)
            path.chmod(0o600)
            user_owned(path)
            self.record('watch_activation_failure', length=len(payload), summary=failure_summary(payload))
            raise RuntimeError(f'Watch reported activation failure (PBB type 12); payload saved to {path}')
        elif kind == 20:
            status = one(protobuf(payload), 1)
            if status not in (1.0, 2.0):
                raise ValueError('Unrecognized Watch language/locale status')
            self.language_done = True
            if status == 2 and not self.activation:
                await self.ids.send(PBB, 36)
                await self.ids.send(PBB, 11)
            self.record('watch_locale_complete', relaunched=status == 2)
        elif kind == 18 and self.prepare and message['peer'].upper() == self.prepare['id']:
            if not self.completion:
                await self.ids.send(PREFS, 0, preferences('com.apple.nanoprefsyncd', {'past-initial-sync': True}))
                self.completion = await self.ids.send(PSY, 0, sync_state(True), flags=4)
                self.update_sync_complete()
                await self.ids.send(PBB, 19, field(1, 100.0) + field(2, 3))
                await self.ids.send(PBB, 3, field(1, 10))
                await self.ids.send(NANO_C, 4, flags=1)
                self.record('initial_sync_completion_published')

    async def advance(self):
        if self.peer_info and self.local_info_ack and not self.store.data.get('ids_device_info_exchanged'):
            self.store.save(ids_device_info_exchanged=True)
            self.record('ids_device_info_exchange_checkpointed')
        if self.reconnecting:
            if self.peer_info and self.local_info_ack and self.property_request is None:
                self.property_request = await self.ids.send(NANO_C, 4, flags=1)
            return
        if self.peer_info and self.local_info_ack and self.check is None:
            await self.ids.wait_transport_quiet(minimum_wait=0.04)
            self.check = await self.ids.send(NANO_D, 3, self.pairing_mode(1))
        required = ('productType', 'modelNumber', 'chipID', 'capabilities')
        if self.property_request and not self.configured and all(self.watch.get(name) is not None for name in required):
            if not isinstance(self.watch['capabilities'], list) or not self.watch['capabilities']:
                raise ValueError('Watch capability snapshot is invalid')
            self.configured = True
            await self.ids.send(NANO_D, 3, self.pairing_mode(3))
            # Authorized full-setup request includes committing the pairing.
            # A resumed setup re-sends the commit; never downgrade a Watch that already confirmed activation.
            self.store.save(paired=True, watch_product=self.product,
                            stage='activation_confirmed' if self.store.data.get('activation_confirmed') else 'pairing_committed')
            self.normal = await self.ids.send(NANO_D, 3, self.pairing_mode(4))
            await self.ids.send(PBB, 111, field(1, self.timezone))
            # Retaining an already matching Watch locale avoids a setup relaunch.
            languages = self.watch.get('preferredLanguages') or [self.language]
            locale = self.watch.get('currentUserLocale') or self.locale
            settings = archive({'AppleLanguages': languages, 'AppleLocale': locale}, 'PBBridgeLocalePreferencesKey')
            await self.ids.send(PBB, 25, b''.join(field(1, lang) for lang in languages) + field(2, locale) + field(3, settings))
            await self.ids.send(PBB, 11)
            self.record('pairing_committed_and_activation_started')
        if self.configured and self.activation and self.language_done and not self.normal_sent:
            self.normal_sent = True
            await self.ids.send(PBB, 36)
            await self.ids.send(PSY, 0, sync_state(False), flags=4)
            self.prepare = await self.ids.send(PBB, 21, flags=1)
            self.record('initial_sync_prepare_sent')
