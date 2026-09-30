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
# source_ref  ("c/<channelId>/<msgId>"  or  "<username>/<msgId>")
# --------------------------------------------------------------------------

_PRIVATE_RE = re.compile(r"^c/(\d{4,15})/(\d{1,10})$")
_PUBLIC_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]{3,31})/(\d{1,10})$")


@dataclass(frozen=True)
class SourceRef:
    kind: str  # 'private' | 'public'
    peer: object  # int channel id (private) or str username (public)
    msg_id: int


def parse_source_ref(sr: str) -> Optional[SourceRef]:
    m = _PRIVATE_RE.match(sr or "")
    if m:
        return SourceRef("private", int(m.group(1)), int(m.group(2)))
    m = _PUBLIC_RE.match(sr or "")
    if m:
        return SourceRef("public", m.group(1), int(m.group(2)))
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


def client_ip(xff: Optional[str], remote: Optional[str], trusted_hops: int = 1) -> str:
    """The FIRST entry of X-Forwarded-For — the original client, with
    every hop after it (Cloudflare, Render's own internal load balancer,
    etc.) appending ITS OWN address afterwards rather than rewriting the
    front. This deliberately mirrors ../lib/requestInfo.ts's
    getClientIp() on the Next.js/Vercel side (forwardedFor.split(',')[0])
    byte-for-byte, since a token minted there and checked here must
    agree on what "the client's IP" even means, or every request looks
    like an IP mismatch regardless of who's actually asking.

    trusted_hops is accepted for backwards-compat signature stability
    but no longer changes which entry is picked — see the fix history in
    tg-stream/README.md if this ever needs to become more elaborate
    (e.g. an untrusted hop somehow ending up in FRONT of the real
    client's own entry, which no reverse proxy in this deployment does).
    """
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
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


@dataclass
class SessionStore:
    ttl: float
    _s: dict = field(default_factory=dict)

    def register(self, jti: str, ip_hash: str, now: Optional[float] = None) -> SessionState:
        now = time.time() if now is None else now
        st = self._s.get(jti)
        if st is None:
            st = SessionState(exp=now + self.ttl, ip=ip_hash)
            self._s[jti] = st
        else:
            st.exp = now + self.ttl
            st.ip = ip_hash
        return st

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
