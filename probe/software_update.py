"""Native OTA state/terms controls. Never accepts terms or starts an update automatically."""
import asyncio
import hashlib
from html.parser import HTMLParser
import os
import plistlib
import re
import tempfile
import time

from apple_codec import Archive, LIMIT, bplist
from pairing_store import user_owned

TOPIC = 'com.apple.private.alloy.otaupdate'


class TermsText(HTMLParser):
    """Render captured HTML as text, preserving link destinations; no fetching."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.hidden, self.links = [], 0, []

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head'):
            self.hidden += 1
        if self.hidden:
            return
        if tag in ('p', 'div', 'br', 'li', 'h1', 'h2', 'h3', 'tr'):
            self.parts.append('\n')
        if tag == 'a':
            self.links.append(dict(attrs).get('href', ''))

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'head'):
            self.hidden = max(0, self.hidden - 1)
        elif not self.hidden:
            if tag == 'a' and self.links:
                link = self.links.pop()
                if link.startswith(('https://', 'http://')):
                    self.parts.append(' (' + link + ')')
            if tag in ('p', 'div', 'li', 'h1', 'h2', 'h3', 'tr'):
                self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def descriptor_info(encoded):
    a = Archive(encoded, 'root')
    descriptor = a.root
    if not isinstance(descriptor, dict) or a.classname(descriptor) != 'SUBDescriptor':
        raise ValueError('Expected SUBDescriptor')
    def text(value, maximum):
        result = a.decode(value)
        if result is None:
            return ''
        if not isinstance(result, str) or len(result.encode('utf-8')) > maximum:
            raise ValueError('Invalid update text')
        return result
    version = text(descriptor.get('productVersion'), 128)
    build = text(descriptor.get('productBuildVersion'), 128)
    documentation = a.ref(descriptor.get('documentation'))
    terms = ''
    license_bytes = b''
    if documentation is not None:
        if not isinstance(documentation, dict) or a.classname(documentation) != 'SUBDocumentation':
            raise ValueError('Expected SUBDocumentation')
        license_value = a.decode(documentation.get('licenseAgreement'))
        if isinstance(license_value, bytes):
            if len(license_value) > 256 * 1024:
                raise ValueError('Update terms exceed size limit')
            license_bytes = license_value
            license_value = license_value.decode('utf-8-sig')
        if license_value is not None:
            if not isinstance(license_value, str) or len(license_value.encode('utf-8')) > 256 * 1024:
                raise ValueError('Invalid update terms')
            if not license_bytes:
                license_bytes = license_value.encode('utf-8')
            if re.search(r'<(?:!doctype|html|body|p|div)\b', license_value, re.I):
                parser = TermsText()
                parser.feed(license_value)
                parser.close()
                terms = '\n'.join(' '.join(line.split()) for line in ''.join(parser.parts).splitlines() if line.strip())
            else:
                terms = license_value
    accepted = a.ref(descriptor.get('userDidAcceptTermsAndConditions'))
    if type(accepted) not in (bool, int) or accepted not in (0, 1):
        accepted = None
    token = hashlib.sha256(bplist({'version': version, 'build': build, 'license': license_bytes})).hexdigest()
    return {'version': version, 'build': build, 'accepted': bool(accepted) if accepted is not None else None,
            'terms': terms, 'token': token}


class SoftwareUpdate:
    def __init__(self, flow):
        self.flow = flow
        self.directory = flow.store.directory / 'software-update'
        self.descriptor = None
        self.details = {}
        self.updated = 0
        self.manager_state = None
        self.query_state = 'not_requested'
        self.acceptance_state = 'not_requested'
        self.acceptance_token = None
        self.terms_request = 0
        self.viewed = None
        self.pending = {}
        self.early_replies = {}
        self.busy = False

    def save(self, name, data):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink():
            raise ValueError('Unsafe OTA directory')
        self.directory.chmod(0o700)
        user_owned(self.directory)
        fd, temporary = tempfile.mkstemp(prefix='.ota-', dir=self.directory)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            path = self.directory / name
            os.replace(temporary, path)
            user_owned(path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def snapshot(self):
        for pending in self.pending.values():
            if time.time() - pending['time'] > 120:
                name = 'query_state' if pending['operation'] == 'query' else 'acceptance_state'
                if getattr(self, name) == 'sent':
                    setattr(self, name, 'reply_unconfirmed')
        return {'version': self.details.get('version'), 'build': self.details.get('build'),
                'terms_available': bool(self.details.get('terms', '').strip()),
                'token': self.details.get('token'), 'watch_accepted': self.details.get('accepted'),
                'query_state': self.query_state, 'acceptance_state': self.acceptance_state,
                'acceptance_token': self.acceptance_token, 'terms_request': self.terms_request,
                'manager_state': self.manager_state, 'updated_at': self.updated or None}

    def terms(self):
        text = self.details.get('terms', '')
        if not text.strip() or not self.descriptor:
            raise ValueError('No terms received for this update')
        self.viewed = self.details['token']
        return {'ok': True, 'text': text, 'token': self.viewed,
                'version': self.details['version'], 'build': self.details['build']}

    async def send(self, operation, token=None):
        if self.busy:
            raise ValueError('An update request is in flight')
        if operation not in ('query', 'accept'):
            raise ValueError('Unsupported update operation')
        if operation == 'accept':
            if self.details.get('accepted') is True:
                raise ValueError('The Watch already reports these terms accepted')
            if (not self.descriptor or not self.details.get('terms', '').strip()
                    or not token or token != self.details.get('token') or token != self.viewed):
                raise ValueError('View the current update terms before accepting')
            if not self.details.get('version') or not self.details.get('build'):
                raise ValueError('Update identity is incomplete')
            if self.acceptance_state in ('sending', 'sent', 'reply_unconfirmed', 'send_outcome_unknown',
                                          'reply_success', 'watch_notification_received'):
                raise ValueError('Acceptance already submitted; query state instead of replaying')
            # The native receiver matches this exact unmodified descriptor against
            # its current update before setting acceptance. Do not flip its bool.
            body = {'MessageType': 'UserDidAcceptTermsAndConditionsWithReply', 'Descriptor': self.descriptor}
        else:
            body = {'MessageType': 'QueryManagerState'}
            if self.query_state == 'sent' and any(p['operation'] == 'query' and time.time() - p['time'] < 15
                                                  for p in self.pending.values()):
                raise ValueError('State query already pending')
        self.busy = True
        name = 'query_state' if operation == 'query' else 'acceptance_state'
        setattr(self, name, 'sending')
        try:
            sent = await asyncio.wait_for(self.flow.ids.send(TOPIC, None, bplist(body), flags=5),
                                          120 if operation == 'accept' else 15)
            self.pending = {k: v for k, v in self.pending.items() if time.time() - v['time'] < 180}
            if len(self.pending) >= 8:
                self.pending.pop(next(iter(self.pending)))
            identifier = sent['id'].upper()
            self.pending[identifier] = {'operation': operation, 'time': time.time(), 'token': token}
            setattr(self, name, 'sent')
            self.flow.record('ota_control_sent', operation=operation, sequence=sent['sequence'],
                             acceptance_confirmed=False)
            if identifier in self.early_replies:
                self.reply(identifier, self.early_replies.pop(identifier))
            return {'ok': True, 'state': getattr(self, name), 'acceptance_confirmed': False}
        except BaseException:
            setattr(self, name, 'send_outcome_unknown')
            self.flow.record('ota_control_unconfirmed', operation=operation, acceptance_confirmed=False)
            raise
        finally:
            self.busy = False
            self.early_replies.clear()

    def reply(self, identifier, body):
        pending = self.pending.pop(identifier, None)
        if not pending:
            if self.busy and len(self.early_replies) < 8:
                self.early_replies[identifier] = body
            return
        if time.time() - pending['time'] > 120:
            return
        operation = pending['operation']
        if operation == 'query':
            self.query_state = 'received' if type(body.get('ManagerState')) is int else 'invalid_reply'
        elif pending['token'] != self.details.get('token'):
            # A descriptor flag update can change the token before the reply.
            self.acceptance_state = 'watch_reported' if self.details.get('accepted') is True else 'update_changed'
        elif body == {} or ('Error' in body and body['Error'] is None):
            # Live 23T240 omits the null Error field: its correlated success
            # completion is an empty dictionary. Uncorrelated bodies cannot reach here.
            self.acceptance_state = 'reply_success'
            self.acceptance_token = pending['token']
        elif isinstance(body.get('Error'), bytes):
            self.acceptance_state = 'reply_error'
        else:
            self.acceptance_state = 'invalid_reply'
        self.flow.record('ota_control_reply', operation=operation,
                         state=getattr(self, 'query_state' if operation == 'query' else 'acceptance_state'),
                         acceptance_confirmed=self.details.get('accepted') is True)

    def receive(self, message):
        payload = message['payload']
        if not 1 <= len(payload) <= LIMIT:
            raise ValueError('Invalid OTA message length')
        body = plistlib.loads(payload)
        if not isinstance(body, dict):
            raise ValueError('Invalid OTA message')
        kind = body.get('MessageType')
        if kind is not None and (not isinstance(kind, str) or not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,95}', kind)):
            raise ValueError('Invalid OTA message type')
        self.save('latest-message.plist', payload)
        if kind == 'DisplayTerms':
            self.terms_request += 1
            self.flow.record('ota_terms_requested', request=self.terms_request)
        if type(body.get('ManagerState')) is int:
            self.manager_state = body['ManagerState']
        if 'Descriptor' in body:
            raw = body['Descriptor']
            if isinstance(raw, bytes):
                # Clear first: malformed/new descriptors cannot authorize stale acceptance.
                previous = self.details
                viewed = self.viewed
                self.save('latest-descriptor.archive', raw)
                self.descriptor, self.details, self.viewed = None, {}, None
                info = descriptor_info(raw)
                self.descriptor, self.details = raw, info
                self.viewed = viewed if viewed == info['token'] else None
                if previous.get('token') != info['token']:
                    self.acceptance_state = 'not_requested'
                    self.acceptance_token = None
                if info['terms']:
                    self.save('terms.txt', info['terms'].encode('utf-8'))
                self.flow.record('ota_descriptor_observed', version=info['version'], build=info['build'],
                                 terms_available=bool(info['terms'].strip()), watch_accepted=info['accepted'])
                if info['accepted'] is True:
                    self.acceptance_state = 'watch_reported'
            elif raw is None:
                self.descriptor, self.details, self.viewed = None, {}, None
            else:
                self.descriptor, self.details, self.viewed = None, {}, None
                raise ValueError('Invalid update descriptor encoding')
        if kind == 'UserDidAcceptTermsAndConditionsChanged':
            accepted = body.get('UserDidAcceptTermsAndConditionsKey')
            if isinstance(accepted, bytes):
                try:
                    a = Archive(accepted, 'root')
                    accepted = a.decode(a.root)
                except (ValueError, KeyError, TypeError, plistlib.InvalidFileException):
                    accepted = None
            if type(accepted) is bool and self.descriptor:
                # The notification has no update identity. Query the descriptor
                # to confirm its acceptance flag for the selected update.
                if self.acceptance_state not in ('reply_success', 'watch_reported'):
                    self.acceptance_state = 'watch_notification_received' if accepted else 'watch_notification_declined'
                self.flow.record('ota_terms_watch_reported', accepted=accepted)
        self.updated = time.time()
        # Raw Data replies have no protobuf response flag; the peer UUID binds them.
        peer = (message.get('peer') or '').upper()
        if peer:
            self.reply(peer, body)
