"""Bounded protobuf, NanoRegistry and NSKeyedArchiver wire formats."""
import math
import plistlib
import struct
import time
import uuid

LIMIT = 1024 * 1024
ARCHIVE_KEY = 'PBBridgeActivationRequestKey'
NANO_D = 'com.apple.private.alloy.bluetoothregistry'
NANO_C = 'com.apple.private.alloy.bluetoothregistryclassc'
PBB = 'com.apple.private.alloy.pbbridge'
PSY = 'com.apple.private.alloy.preferencessync.pairedsync'
PREFS = 'com.apple.private.alloy.preferencessync'
CREDS = 'com.apple.private.alloy.idscredentials'
TIMESYNC = 'com.apple.private.alloy.timesync'
APPSYNC = 'com.apple.private.alloy.appsyncconduit.v2'
# Topics the reference routes on the Class-D lane (IdsApplicationRoute.forTopic); everything else is Class-C.
CLASS_D_TOPICS = (CREDS, NANO_D, PREFS, TIMESYNC, 'com.apple.private.alloy.timezonesync',
                  'com.apple.private.alloy.clockface.sync', 'com.apple.private.alloy.bulletinboard.settings')

# kTMLSLink time-sync dictionaries as observed on the Class-D timesync topic.
TM_MSG, TM_REQUEST_STATE, TM_ACK, TM_CONVERT = 'kTMLSLinkMsgKey', 6, 7, 8


def timesync_message_type(payload):
    try:
        value = plistlib.loads(payload)
        kind = value.get(TM_MSG) if isinstance(value, dict) else None
        return kind if type(kind) is int else -1
    except Exception:
        return -1


def timesync_state_replies(timezone):
    """Answer to kTMLSLinkMsgKey=6: automatic time on (12), request ack (7), source and time zone (4)."""
    return [bplist({'kTMLSLinkAutomaticTimeEnabledKey': True, TM_MSG: 12}),
            bplist({TM_MSG: 7}),
            bplist({TM_MSG: 4, 'kTMLSLinkSourceKey': 'TMLSSourceDevice', 'kTMLSLinkTimeZoneKey': timezone})]


def timesync_clock_replies(request, unix_seconds, monotonic_seconds):
    """Answer to the Bluetooth clock-conversion request (8): conversion (9) then current device time (1)."""
    value = plistlib.loads(request)
    mach, rtc, error = (value.get(name) for name in ('kTMLSLinkRemoteMachKey', 'kTMLSLinkRTCKey', 'kTMLSLinkUncertaintyKey'))
    if (not isinstance(value, dict) or value.get(TM_MSG) != TM_CONVERT
            or any(isinstance(n, bool) or not isinstance(n, (int, float)) for n in (mach, rtc, error))
            or mach <= 0 or rtc <= 0 or not 0 <= error <= 60):
        raise ValueError('Invalid Bluetooth time conversion request')
    return [bplist({TM_MSG: 9, 'kTMLSLinkRTCKey': mach / 1e9, 'kTMLSLinkRemoteRTCKey': float(rtc),
                    'kTMLSLinkUncertaintyKey': error + 0.001}),
            bplist({TM_MSG: 1, 'kTMLSLinkTimeKey': unix_seconds - 978307200.0, 'kTMLSLinkRTCKey': monotonic_seconds,
                    # Watch LinkSource 23T240 accepts only Computed/ComputedReliable
                    # for time updates (0x37c0..0x37f4); Device is for the zone.
                    'kTMLSLinkUncertaintyKey': 0.1, 'kTMLSLinkSourceKey': 'TMLSSourceComputed',
                    'kTMLSLinkReliableKey': False})]


def varint(number):
    if number < 0:
        number &= 0xffffffffffffffff
    if number >= 1 << 64:
        raise ValueError('Protobuf integer exceeds uint64')
    out = bytearray()
    while number > 127:
        out.append((number & 127) | 128)
        number >>= 7
    return bytes(out) + bytes([number])


def field(number, value, wire=None):
    if not 1 <= number < 1 << 29:
        raise ValueError('Invalid protobuf field number')
    if isinstance(value, str):
        value = value.encode()
    if wire == 1 or isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError('Nonfinite protobuf double')
        return varint(number << 3 | 1) + struct.pack('<d', value)
    if isinstance(value, bytes):
        return varint(number << 3 | 2) + varint(len(value)) + value
    return varint(number << 3) + varint(int(value))


def protobuf(data):
    if len(data) > LIMIT:
        raise ValueError('Protobuf exceeds size limit')
    offset, out = 0, {}
    def readvar():
        nonlocal offset
        number = 0
        for n in range(10):
            if offset >= len(data):
                raise ValueError('Truncated protobuf varint')
            byte = data[offset]
            offset += 1
            if n == 9 and byte > 1:
                raise ValueError('Protobuf integer overflow')
            number |= (byte & 127) << (n * 7)
            if byte < 128:
                return number
        raise ValueError('Invalid protobuf varint')
    count = 0
    while offset < len(data):
        tag = readvar()
        number, wire = tag >> 3, tag & 7
        count += 1
        if not number or count > 4096:
            raise ValueError('Invalid or excessive protobuf fields')
        if wire == 0:
            value = readvar()
        elif wire in (1, 2, 5):
            size = readvar() if wire == 2 else 8 if wire == 1 else 4
            if size > len(data) - offset:
                raise ValueError('Truncated protobuf field')
            value = data[offset:offset + size]
            offset += size
            if wire == 1:
                value = struct.unpack('<d', value)[0]
        else:
            raise ValueError('Unsupported protobuf wire type')
        out.setdefault(number, []).append(value)
    return out


def one(fields, number, default=None):
    values = fields.get(number, [])
    if len(values) > 1:
        raise ValueError('Duplicate singular protobuf field')
    return values[0] if values else default


def bplist(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)


def archive(value, key):
    objects = ['$null']
    classes = {}
    def append(obj):
        index = len(objects)
        objects.append(obj)
        return plistlib.UID(index)
    def descriptor(name):
        if name not in classes:
            classes[name] = append({'$classname': name, '$classes': [name, 'NSObject']})
        return classes[name]
    def encode(obj, depth=0):
        if depth > 16:
            raise ValueError('Archive exceeds depth limit')
        if isinstance(obj, dict):
            keys = [encode(k, depth + 1) for k in obj]
            values = [encode(v, depth + 1) for v in obj.values()]
            return append({'NS.keys': keys, 'NS.objects': values, '$class': descriptor('NSDictionary')})
        if isinstance(obj, list):
            return append({'NS.objects': [encode(v, depth + 1) for v in obj], '$class': descriptor('NSArray')})
        if isinstance(obj, (str, bytes, int, float, bool)):
            return append(obj)
        raise ValueError('Unsupported archived object')
    root = encode(value)
    return bplist({'$version': 100000, '$archiver': 'NSKeyedArchiver', '$top': {key: root}, '$objects': objects})


class Archive:
    def __init__(self, encoded, key):
        if len(encoded) > LIMIT:
            raise ValueError('Keyed archive exceeds size limit')
        root = plistlib.loads(encoded)
        if not isinstance(root, dict) or root.get('$version') != 100000 or root.get('$archiver') != 'NSKeyedArchiver':
            raise ValueError('Invalid keyed archive')
        self.objects = root['$objects']
        if not isinstance(self.objects, list) or not 1 <= len(self.objects) <= 8192:
            raise ValueError('Invalid archive object table')
        self.root = self.ref(root['$top'][key])

    def ref(self, value):
        if isinstance(value, plistlib.UID):
            if value.data >= len(self.objects):
                raise ValueError('Archive reference exceeds object table')
            return None if value.data == 0 else self.objects[value.data]
        return value

    def classname(self, obj):
        cls = self.ref(obj.get('$class'))
        return cls.get('$classname') if isinstance(cls, dict) else None

    def decode(self, value, depth=0):
        if depth > 16:
            raise ValueError('Cyclic or excessive keyed archive')
        obj = self.ref(value)
        if isinstance(obj, dict):
            cls = self.classname(obj)
            if cls in ('NSDictionary', 'NSMutableDictionary'):
                keys, values = obj.get('NS.keys'), obj.get('NS.objects')
                if not isinstance(keys, list) or not isinstance(values, list) or len(keys) != len(values) or len(keys) > 512:
                    raise ValueError('Invalid archived dictionary')
                result = {}
                for key, value in zip(keys, values):
                    key = self.decode(key, depth + 1)
                    if not isinstance(key, str) or key in result:
                        raise ValueError('Invalid or duplicate archive dictionary key')
                    result[key] = self.decode(value, depth + 1)
                return result
            if cls in ('NSArray', 'NSMutableArray'):
                return [self.decode(v, depth + 1) for v in obj['NS.objects']]
            if cls in ('NSData', 'NSMutableData'):
                return self.decode(obj['NS.data'], depth + 1)
            if cls in ('NSString', 'NSMutableString'):
                return self.decode(obj['NS.string'], depth + 1)
            raise ValueError('Unsupported secure archive object class')
        if obj is None or isinstance(obj, (bytes, str, bool, float, int)):
            return obj
        raise ValueError('Invalid secure archive value')


def activation_request(encoded):
    a = Archive(encoded, ARCHIVE_KEY)
    request = a.root
    if not isinstance(request, dict) or a.classname(request) not in ('NSURLRequest', 'NSMutableURLRequest'):
        raise ValueError('Activation archive is not a URL request')
    if not 1 <= request.get('$0', 0) <= 10 or not 7 <= request.get('$1', 0) <= 20 or request.get('$2', 0) < 21:
        raise ValueError('Unsupported URL request archive version')
    def prop(index):
        return request['__nsurlrequest_proto_prop_obj_' + str(index)]
    url = a.ref(prop(1))
    if not isinstance(url, dict) or a.classname(url) != 'NSURL' or a.ref(url.get('NS.base')) is not None:
        raise ValueError('Invalid activation URL')
    url = a.decode(url['NS.relative'])
    method, headers, body = a.decode(prop(18)), a.decode(prop(19)), a.decode(prop(20))
    timeout = a.ref(prop(2))
    if method != 'POST' or not isinstance(headers, dict) or not isinstance(body, bytes) or not body:
        raise ValueError('Invalid activation method, headers or body')
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ValueError('Invalid activation timeout')
    seen, accepted = set(), {}
    token = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    total = 0
    if len(headers) > 256:
        raise ValueError('Invalid activation HTTP header: too many headers')
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError('Invalid activation HTTP header: non-string name or value')
        if name == '__hhaa__':
            # CFNetwork's shadowed header-array metadata is not an HTTP header (CFNetwork bookkeeping, not a header).
            if not value or len(value) > 65536 or '\0' in value:
                raise ValueError('Invalid activation HTTP header: malformed shadowed metadata')
            continue
        if not name or not value or len(name) > 65536 or len(value) > 65536:
            raise ValueError('Invalid activation HTTP header: empty or oversized component')
        if any(c not in token for c in name):
            raise ValueError('Invalid activation HTTP header: forbidden character in name')
        if any(c in '\r\n\0' or ord(c) < 0x20 and c != '\t' for c in value):
            raise ValueError('Invalid activation HTTP header: forbidden character in value')
        if name.lower() in seen:
            raise ValueError('Invalid activation HTTP header: duplicate name')
        total += len(name) + len(value)
        if total > 262144:
            raise ValueError('Invalid activation HTTP header: headers too large')
        seen.add(name.lower())
        accepted[name] = value
    headers = accepted
    return url, headers, body, timeout


def nr_number(value, unsigned=False):
    if isinstance(value, bool):
        return field(2, field(4, value))
    return field(2, field(5 if unsigned else 1, value) + field(6, unsigned))


def nr_value(value):
    if isinstance(value, str):
        return field(1, value)
    if isinstance(value, bytes):
        return field(4, value)
    if isinstance(value, uuid.UUID):
        return field(3, value.bytes)
    if isinstance(value, (bool, int)):
        return nr_number(value)
    if isinstance(value, list):
        return b''.join(field(7, nr_value(item)) for item in value)
    if isinstance(value, set):
        return b''.join(field(7, nr_value(item)) for item in sorted(value, key=str)) + field(8, True)
    raise ValueError('Unsupported NanoRegistry property value')


def nr_properties(values, full=True, born_on=None, response=False):
    out = b'' if response else field(1, full)
    for name, value in values.items():
        encoded = nr_number(value, unsigned=True) if name == 'chipID' and type(value) is int else nr_value(value) if value is not None else None
        prop = field(1, name) + (field(2, encoded) if encoded is not None else b'')
        out += field(1 if response else 2, prop)
    if born_on is not None and not response:
        out += field(3, born_on)
    return out


def decode_nr_properties(payload, response=False):
    root = protobuf(payload)
    result = {}
    def decode(value, depth=0):
        if depth > 16:
            raise ValueError('NanoRegistry property exceeds depth limit')
        v = protobuf(value)
        if 1 in v:
            return one(v, 1).decode()
        if 2 in v:
            number = protobuf(one(v, 2))
            for tag in (1, 3, 4, 5):
                if tag in number:
                    return bool(one(number, tag)) if tag == 4 else one(number, tag)
        if 3 in v:
            return str(uuid.UUID(bytes=one(v, 3)))
        if 4 in v:
            return one(v, 4)
        if 7 in v:
            return [decode(item, depth + 1) for item in v[7]]
        return None
    for encoded in root.get(1 if response else 2, []):
        prop = protobuf(encoded)
        name = one(prop, 1).decode()
        if name in result:
            raise ValueError('Duplicate NanoRegistry property')
        value = one(prop, 2)
        result[name] = decode(value) if value is not None else None
    return result


def apple_time():
    return time.time() - 978307200


def preferences(domain, values):
    return (field(1, apple_time()) + field(2, domain)
            + b''.join(field(3, field(1, name) + field(2, bplist(value))) for name, value in values.items()))


def sync_state(complete=False):
    state = 3 if complete else 2
    client = {'version': 1, 'syncProgressState': state, 'syncSessionType': 0, 'migrationSync': False}
    if not complete:
        client.update(activeActivityLabels=['InitialSync'], completedActivityLabels=[])
    return preferences('com.apple.pairedsync', {'PSYWatchSyncState': {'version': 1, 'syncProgressState': state,
                        'globalProgress': 100 if complete else 0}, 'PSYWatchSyncClientState': client})
