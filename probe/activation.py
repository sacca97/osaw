"""Apple's watch-generated HTTPS requests, relayed without changing ticket bytes."""
import asyncio
from urllib.parse import urlsplit
import re
from pathlib import Path
from apple_codec import ARCHIVE_KEY, activation_request, archive, field
from pairing_store import user_owned


def classify_body(body):
    """Shape of an Apple activation answer. Albert returns a small plist with ActivationRecord on success;
    an HTML page is a challenge (Find My / Activation Lock form, alert or retry page) the Watch cannot use."""
    text = body.decode('utf-8', 'ignore')
    if 'ActivationRecord' in text:
        return {'kind': 'activation-record'}
    if re.search(r'<html|<!doctype html', text[:2048], re.I):
        title = re.search(r'<title>(.{0,80}?)</title>', text, re.I | re.S)
        lowered = text.lower()
        return {'kind': 'html-page', 'title': title.group(1).strip() if title else None,
                'mentions': [word for word in ('fmip', 'activation lock', 'find my', 'apple id', 'password')
                             if word in lowered]}
    if text.lstrip().startswith('<'):
        return {'kind': 'xml'}
    return {'kind': 'other'}


def validate_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.fragment
            or not (parsed.hostname == 'apple.com' or parsed.hostname.endswith('.apple.com'))):
        raise ValueError('Activation endpoint must be an Apple HTTPS URL on port 443')
    return url


class ActivationProxy:
    def __init__(self, record, directory=None):
        import httpx
        self.directory, self.count = Path(directory) if directory else None, 0
        self.httpx = httpx
        # HTTPX defaults to verified certificates. No client identity is invented.
        self.client = httpx.Client(http2=False, follow_redirects=True, max_redirects=20, trust_env=False,
            event_hooks={'request': [lambda request: validate_url(str(request.url))]})
        self.record = record

    def exchange(self, encoded):
        url, headers, body, timeout = activation_request(encoded)
        validate_url(url)
        headers = {name: value for name, value in headers.items()
                   if name.lower() not in ('x-ios-activation-medium', 'host', 'content-length')}
        headers['X-iOS-Activation-Medium'] = 'WiFi'
        for attempt in range(2):
            try:
                with self.client.stream('POST', url, headers=headers, content=body, timeout=timeout) as response:
                    if response.status_code != 200:
                        raise RuntimeError(f'Apple activation HTTP status {response.status_code}')
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > 1024 * 1024:
                            raise ValueError('Activation response exceeds size limit')
                        chunks.append(chunk)
                    result = b''.join(chunks)
                    if not result:
                        raise ValueError('Empty activation server response')
                    # httpx lower-cases names in .items() (and HTTP/2 does on the wire). The Watch decodes a plain
                    # case-sensitive NSDictionary, so keep the server's spelling (e.g. ARS) and fold duplicates.
                    response_headers = {}
                    for raw_name, raw_value in response.headers.raw:
                        name, value = raw_name.decode('latin1'), raw_value.decode('latin1')
                        existing = next((key for key in response_headers if key.lower() == name.lower()), None)
                        if existing is None:
                            response_headers[name] = value
                        else:
                            response_headers[existing] += ', ' + value
                    self.count += 1
                    if self.directory is not None:
                        # Private research artifact for the user; may contain account details.
                        saved = self.directory / f'activation-response-{self.count}.bin'
                        saved.write_bytes(result)
                        saved.chmod(0o600)
                        user_owned(saved)
                    self.record('activation_https_response', status=response.status_code,
                                shape=classify_body(result),
                                protocol=response.http_version, body_length=len(result),
                                header_names=sorted(response_headers))
                    # Exact application body, including XML whitespace and ordering.
                    return field(1, result) + field(2, archive(response_headers, ARCHIVE_KEY))
            except self.httpx.TransportError:
                if attempt:
                    raise
        raise AssertionError('Unreachable activation retry state')

    async def relay(self, encoded):
        return await asyncio.to_thread(self.exchange, encoded)

    def close(self):
        self.client.close()
