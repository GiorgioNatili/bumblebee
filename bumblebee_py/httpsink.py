"""
HTTP sink for the output layer.

Buffers NDJSON records in memory and POSTs them in fixed-size batches
to a generic HTTPS log-ingest endpoint.
"""

import gzip
import hashlib
import hmac
import io
import json
import threading
import time
from typing import Optional
from urllib.parse import urlparse

from bumblebee_py.emitter import SinkStats

_CONTENT_TYPE_NDJSON = "application/x-ndjson"
_DEFAULT_BATCH_SIZE = 500
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_HMAC_HEADER = "X-Inventory-Signature"
_MAX_RESPONSE_SNIPPET = 512


class HTTPAuth:
    """Describes how an HTTPSink authenticates each request."""

    def __init__(self, mode: str = "none", token: str = "",
                 hmac_key: bytes = b"", hmac_header: str = "",
                 timestamp_header: str = ""):
        self.mode = mode          # "none", "bearer", "hmac-sha256"
        self.token = token
        self.hmac_key = hmac_key
        self.hmac_header = hmac_header
        self.timestamp_header = timestamp_header


class HTTPConfig:
    """Configuration for HTTPSink."""

    def __init__(self, url: str = "", auth: Optional[HTTPAuth] = None,
                 timeout: float = _DEFAULT_TIMEOUT,
                 batch_size: int = _DEFAULT_BATCH_SIZE,
                 user_agent: str = "",
                 allow_insecure: bool = False,
                 gzip: bool = False):
        self.url = url
        self.auth = auth or HTTPAuth()
        self.timeout = timeout
        self.batch_size = batch_size
        self.user_agent = user_agent
        self.allow_insecure = allow_insecure
        self.gzip = gzip
        #: Test hook: inject a stub HTTP client.
        self.http_client = None


class HTTPSink:
    """Buffered NDJSON HTTP sink. Thread-safe."""

    def __init__(self, cfg: HTTPConfig):
        self._cfg = cfg
        self._buf = io.StringIO()
        self._in_batch = 0
        self._err: Optional[Exception] = None
        self._closed = False
        self._lock = threading.Lock()
        self._stats = SinkStats()

        # stats_reporter attribute used by Emitter.sink_stats()
        self.stats_reporter = self._get_stats

    def _get_stats(self) -> SinkStats:
        with self._lock:
            return self._stats

    def write(self, data: str) -> int:
        """Write one NDJSON line to the buffer.

        Returns the number of bytes written.
        """
        with self._lock:
            if self._closed:
                raise ValueError("http sink: write after close")
            if self._err:
                raise self._err

            n = len(data)
            self._buf.write(data)
            newlines = data.count("\n")
            if newlines > 0:
                self._in_batch += newlines
            if self._in_batch >= self._cfg.batch_size:
                self._flush_locked()
            return n

    def close(self):
        """Flush any buffered records."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._err:
                return
            if self._buf.tell() == 0:
                return
            self._flush_locked()

    def _flush_locked(self):
        body = self._buf.getvalue()
        self._buf = io.StringIO()
        self._in_batch = 0

        wire_body = body.encode("utf-8")
        if self._cfg.gzip:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(wire_body)
            wire_body = buf.getvalue()

        import urllib.request

        headers = {"Content-Type": _CONTENT_TYPE_NDJSON}
        if self._cfg.gzip:
            headers["Content-Encoding"] = "gzip"
        if self._cfg.user_agent:
            headers["User-Agent"] = self._cfg.user_agent

        self._apply_auth(headers, wire_body)

        req = urllib.request.Request(
            self._cfg.url, data=wire_body, headers=headers, method="POST",
        )

        self._stats.http_batches_attempted += 1
        try:
            resp = urllib.request.urlopen(req, timeout=self._cfg.timeout)
            self._stats.http_last_status = resp.status
            if resp.status < 200 or resp.status >= 300:
                snippet = resp.read(_MAX_RESPONSE_SNIPPET).decode("utf-8", errors="replace")
                self._stats.http_batches_failed += 1
                raise ValueError(
                    f"http sink: server returned {resp.status}: {snippet.strip()}"
                )
            self._stats.http_batches_succeeded += 1
        except Exception as e:
            self._stats.http_batches_failed += 1
            raise

    def _apply_auth(self, headers: dict, body: bytes):
        auth = self._cfg.auth
        if auth.mode == "none":
            return
        if auth.mode == "bearer":
            headers["Authorization"] = f"Bearer {auth.token}"
            return
        if auth.mode == "hmac-sha256":
            signed_payload = body
            if auth.timestamp_header:
                ts = str(int(time.time()))
                headers[auth.timestamp_header] = ts
                signed_payload = (ts + ".").encode("utf-8") + body
            sig = hmac.new(auth.hmac_key, signed_payload, hashlib.sha256).hexdigest()
            hdr = auth.hmac_header or _DEFAULT_HMAC_HEADER
            headers[hdr] = f"sha256={sig}"
            return
        raise ValueError(f"http sink: unknown auth mode {auth.mode!r}")


def validate_http_config(cfg: HTTPConfig) -> Optional[str]:
    """Validate an HTTPConfig. Return None if valid, or an error string."""
    if not cfg.url:
        return "http sink: url is required"
    parsed = urlparse(cfg.url)
    if parsed.scheme not in ("http", "https"):
        return f"http sink: url scheme must be http or https, got {parsed.scheme!r}"
    if parsed.scheme == "http" and not cfg.allow_insecure:
        host = parsed.hostname or ""
        if host != "localhost" and not _is_loopback(host):
            return ("http sink: refusing plain http to non-loopback host; "
                    "use https or set allow-insecure for testing")
    auth = cfg.auth
    if auth and auth.mode == "bearer" and not auth.token:
        return "http sink: bearer auth requires a token"
    if auth and auth.mode == "hmac-sha256" and not auth.hmac_key:
        return "http sink: hmac-sha256 auth requires a key"
    return None


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        import ipaddress
        addr = ipaddress.ip_address(host)
        return addr.is_loopback
    except ValueError:
        return False
