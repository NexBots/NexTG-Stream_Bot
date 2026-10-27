"""
Pure-logic helpers for the Telegram stream server (server.py).

Nothing in here imports aiohttp or Telethon on purpose: token crypto,
Range parsing, source_ref parsing, the chunk cache and the session store
are all unit-tested on their own (see test_core.py), including a
cross-check against the Next.js side's real lib/streamToken.ts.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Token / session-id crypto — byte-for-byte compatible with
# ../lib/streamToken.ts:  base64url( iv[12] || authTag[16] || ciphertext )
# key = sha256(STREAM_TOKEN_SECRET)
# --------------------------------------------------------------------------

IV_LEN = 12
TAG_LEN = 16


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def decrypt_payload(token: str, secret: str) -> Optional[dict]:
    """Returns the decoded JSON payload, or None for ANY problem
    (bad base64, wrong key, tampering, not JSON). Expiry is NOT checked
    here — callers check the field they care about (exp / hx)."""
    try:
        raw = _b64url_decode(token)
        if len(raw) < IV_LEN + TAG_LEN + 2:
            return None
        iv, tag, ct = raw[:IV_LEN], raw[IV_LEN : IV_LEN + TAG_LEN], raw[IV_LEN + TAG_LEN :]
        # `cryptography` wants ciphertext || tag
        plain = AESGCM(derive_key(secret)).decrypt(iv, ct + tag, None)
        data = json.loads(plain.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (InvalidTag, ValueError, UnicodeDecodeError, TypeError):
        return None


def encrypt_payload(payload: dict, secret: str) -> str:
    import os

    iv = os.urandom(IV_LEN)
    sealed = AESGCM(derive_key(secret)).encrypt(iv, json.dumps(payload, separators=(",", ":")).encode(), None)
    ct, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    return _b64url_encode(iv + tag + ct)


def hash_for_token(value: str) -> str:
    """Same as hashForToken() in lib/streamToken.ts."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


# --------------------------------------------------------------------------
# source_ref  ("c/<chatId>/<msgId>"  or  "c/<chatId>/<topicId>/<msgId>"
#              or "<username>/<msgId>" or "<username>/<topicId>/<msgId>")
#
# The 3-part form is what Telegram gives you for a message inside a forum
# group's topic (Topics enabled). The middle number is the topic id; the
# LAST number is always the real message id.
# --------------------------------------------------------------------------

_PRIVATE_RE = re.compile(r"^c/(\d{4,15})(?:/(\d{1,10}))?/(\d{1,10})$")
_PUBLIC_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]{3,31})(?:/(\d{1,10}))?/(\d{1,10})$")


@dataclass(frozen=True)
class SourceRef:
    kind: str  # 'private' | 'public'
    peer: object  # int chat id (private) or str username (public)
    msg_id: int
    topic_id: Optional[int] = None  # forum topic id, informational only


def parse_source_ref(sr: str) -> Optional[SourceRef]:
    m = _PRIVATE_RE.match(sr or "")
    if m:
        topic = int(m.group(2)) if m.group(2) else None
        return SourceRef("private", int(m.group(1)), int(m.group(3)), topic)
    m = _PUBLIC_RE.match(sr or "")
    if m:
        topic = int(m.group(2)) if m.group(2) else None
        return SourceRef("public", m.group(1), int(m.group(3)), topic)
    return None


# --------------------------------------------------------------------------
# HTTP Range
# --------------------------------------------------------------------------


class RangeNotSatisfiable(Exception):
    pass


_RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


def parse_range(header: Optional[str], size: int) -> Optional[tuple[int, int]]:
    """None -> no Range header (send whole file). Otherwise inclusive
    (start, end). Multi-range requests are not supported (browsers don't
    send them for <video>) and are answered as unsatisfiable."""
    if not header:
        return None
    m = _RANGE_RE.match(header.strip())
    if not m:
        raise RangeNotSatisfiable()
    a, b = m.group(1), m.group(2)
    if a == "" and b == "":
        raise RangeNotSatisfiable()
    if a == "":  # suffix: last N bytes
        n = int(b)
        if n == 0:
            raise RangeNotSatisfiable()
        start = max(0, size - n)
        end = size - 1
    else:
        start = int(a)
        end = int(b) if b != "" else size - 1
        end = min(end, size - 1)
    if start >= size or start > end:
        raise RangeNotSatisfiable()
    return start, end


# --------------------------------------------------------------------------
# Client IP behind a reverse proxy (Render's edge, Cloudflare in front of
# it, Caddy, etc.)
# --------------------------------------------------------------------------


def _valid_ip(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    v = v.strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None
    return v


def client_ip(xff: Optional[str], remote: Optional[str], trusted_hops: int = 1, preferred: Optional[str] = None) -> str:
    """The client's IP as seen by this server.

    `preferred` is a header value that the edge in front of us SETS
    (overwriting anything the client sent): Cloudflare's CF-Connecting-IP
    or True-Client-IP. It is the only value a client cannot forge, so it
    wins whenever it is present and is a real IP address.

    Otherwise fall back to X-Forwarded-For, taking the entry the nearest
    trusted proxy appended: `trusted_hops` entries from the RIGHT. (The
    LEFT-most entry is whatever the client chose to send, so using it
    would let anyone pretend to be somebody else's IP.)
    """
    ip = _valid_ip(preferred)
    if ip:
        return ip
    if xff and trusted_hops > 0:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            idx = max(0, len(parts) - trusted_hops)
            ip = _valid_ip(parts[idx])
            if ip:
                return ip
    return remote or "unknown"


# --------------------------------------------------------------------------
# Byte-bounded LRU for downloaded Telegram chunks
# --------------------------------------------------------------------------


class ChunkCache:
    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self._d: "OrderedDict[tuple, bytes]" = OrderedDict()
        self.size = 0

    def get(self, key):
        v = self._d.get(key)
        if v is not None:
            self._d.move_to_end(key)
        return v

    def put(self, key, value: bytes):
        if self.max_bytes <= 0 or len(value) > self.max_bytes:
            return
        old = self._d.pop(key, None)
        if old is not None:
            self.size -= len(old)
        self._d[key] = value
        self.size += len(value)
        while self.size > self.max_bytes and self._d:
            _, ev = self._d.popitem(last=False)
            self.size -= len(ev)


# --------------------------------------------------------------------------
# Playback sessions
# --------------------------------------------------------------------------


@dataclass
class SessionState:
    exp: float  # monotonic-independent unix time; sliding, extended by /session renewals
    ip: str  # hash of the IP that (re)registered it
    conns: int = 0  # currently open media responses
    # Set once, on first registration, from the decrypted token payload
    # (server.py) — kept on the session so later requests bearing the
    # same token don't need to decrypt it again.
    source_ref: str = ""
    uid: str = ""
    aid: str = ""
    born: float = 0.0  # when the session was first registered (absolute cap, never slides)
    ip_changes: int = 0  # how many times the client IP differed from the previous request


@dataclass
class SessionStore:
    ttl: float
    _s: dict = field(default_factory=dict)

    def register(self, jti: str, ip_hash: str, now: Optional[float] = None) -> SessionState:
        now = time.time() if now is None else now
        st = self._s.get(jti)
        if st is None:
            st = SessionState(exp=now + self.ttl, ip=ip_hash, born=now)
            self._s[jti] = st
        else:
            st.exp = now + self.ttl
            if st.ip != ip_hash:
                st.ip_changes += 1
            st.ip = ip_hash
        return st

    def drop(self, jti: str) -> None:
        self._s.pop(jti, None)

    def get(self, jti: str) -> Optional[SessionState]:
        return self._s.get(jti)

    def purge(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        dead = [k for k, v in self._s.items() if v.exp < now and v.conns == 0]
        for k in dead:
            del self._s[k]
        return len(dead)

    def __len__(self):
        return len(self._s)


# --------------------------------------------------------------------------
# Per-viewer (one user x one video) download limits.
#
# A real player reads a video at roughly its bitrate, with short bursts when
# it fills its buffer or the viewer seeks. A "download manager" or a script
# reads as fast as the connection allows, on many connections. These limits
# keep normal playback untouched but make a bulk copy slow, so it takes
# about as long as watching the class, and cap what one account can pull in
# a day. They are keyed on (user, video) — NOT on the token — so asking for
# a fresh token doesn't reset them.
# --------------------------------------------------------------------------

MB = 1024 * 1024


@dataclass
class ViewerState:
    tokens: float  # bytes we may send right now (token bucket)
    last: float  # last refill time
    day_start: float
    day_bytes: int = 0
    conns: int = 0  # open media responses for this viewer+video
    seen: float = 0.0  # last activity, for purging


class DailyLimitExceeded(Exception):
    pass


class ViewerLimiter:
    def __init__(
        self,
        max_conns: int = 4,
        day_factor: float = 6.0,  # a viewer may pull at most this many x the file size per 24h
        rate_factor: float = 3.0,  # sustained speed = this many x the video's own bitrate
        burst_seconds: float = 120.0,  # bucket holds this many seconds of video (at rate_factor)
        min_rate: float = 0.5 * MB,  # never throttle below this (bytes/s) — 4 Mbit/s
        min_burst: float = 32 * MB,
    ):
        self.max_conns = max_conns
        self.day_factor = day_factor
        self.rate_factor = rate_factor
        self.burst_seconds = burst_seconds
        self.min_rate = min_rate
        self.min_burst = min_burst
        self._v: dict = {}

    def params(self, size: int, duration: Optional[float]) -> Optional[tuple[float, float]]:
        """(rate bytes/s, bucket capacity bytes), or None when we can't
        compute a bitrate (unknown duration -> no throttling)."""
        if not duration or duration <= 0 or size <= 0:
            return None
        rate = max(self.min_rate, (size / duration) * self.rate_factor)
        capacity = max(self.min_burst, rate * self.burst_seconds)
        return rate, capacity

    def get(self, key, capacity: float, now: Optional[float] = None) -> ViewerState:
        now = time.time() if now is None else now
        st = self._v.get(key)
        if st is None:
            st = ViewerState(tokens=capacity, last=now, day_start=now)
            self._v[key] = st
        st.seen = now
        return st

    def day_over(self, st: ViewerState, size: int, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        if self.day_factor <= 0:
            return False  # daily cap disabled
        if now - st.day_start > 86400:
            st.day_start, st.day_bytes = now, 0
        return st.day_bytes >= self.day_factor * size

    def take(self, st: ViewerState, n: int, size: int, params: Optional[tuple[float, float]], now: Optional[float] = None) -> float:
        """Account for sending `n` bytes. Returns how many seconds the caller
        must wait before sending (0 = send now). Raises DailyLimitExceeded
        once the 24h budget is used up."""
        now = time.time() if now is None else now
        if self.day_over(st, size, now):
            raise DailyLimitExceeded()
        if params is None:
            st.day_bytes += n
            return 0.0
        rate, capacity = params
        st.tokens = min(capacity, st.tokens + (now - st.last) * rate)
        st.last = now
        if st.tokens >= n:
            st.tokens -= n
            st.day_bytes += n
            return 0.0
        wait = (n - st.tokens) / rate
        st.tokens = 0.0  # we'll have exactly n worth by the time the wait is over
        st.last = now + wait
        st.day_bytes += n
        return wait

    def purge(self, now: Optional[float] = None, idle: float = 2 * 86400) -> int:
        now = time.time() if now is None else now
        dead = [k for k, v in self._v.items() if v.conns == 0 and now - v.seen > idle]
        for k in dead:
            del self._v[k]
        return len(dead)
