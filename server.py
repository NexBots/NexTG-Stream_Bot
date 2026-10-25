"""
tg-stream — relays a video posted in a Telegram channel (public or
private) to NexSecurity's <video> element as an ordinary Range-seekable
HTTP stream, gated by the same short-lived encrypted token pattern the
Cloudflare Worker (../worker/src/index.ts) uses for the 'm3u8' provider.

Flow (see ../lib/telegramStreamToken.ts and
../app/api/video/[id]/telegram-token/route.ts for the Next.js side):

  1. Browser calls POST /api/video/:id/telegram-token (real Supabase
     auth + board-access + concurrent-device checks happen THERE, same
     as every other provider).
  2. Next.js mints a 90s AES-256-GCM token encoding
     {vid, uid, ip, aid, exp, sr} and hands it to the browser.
  3. VideoPlayer.tsx sets <video src="https://tg.example.com/tg/:id?t=...">.
  4. THIS server decrypts `t`, checks vid/exp/ip match, resolves `sr`
     ("c/<channelId>/<msgId>" or "<username>/<msgId>") to a Telegram
     message via one persistent MTProto session (Telethon), and streams
     the requested byte range straight from Telegram — never buffering
     the whole file, never touching disk.
  5. A validated token is remembered as a sliding SESSION (core.SessionStore)
     keyed by a hash of the token string, so the many Range requests one
     video element makes over a 2-5 hour class don't each need a fresh
     token — only the FIRST request per player load needs `t` to still
     be within its 90s mint window. Every request, in or out of that
     window, still has its IP re-checked against the session.

Run: `python3 server.py` (reads config from environment — see README.md
for the full list and for `python3 gen_session.py` to produce
TELEGRAM_SESSION_STRING).
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import time
from collections import deque
from typing import Optional

from aiohttp import web
from telethon import TelegramClient, errors
from telethon.sessions import StringSession
from telethon.tl.types import Channel, Document

import core

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tg-stream")

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

API_ID = int(os.environ["TELEGRAM_API_ID"])
API_HASH = os.environ["TELEGRAM_API_HASH"]
SESSION_STRING = os.environ["TELEGRAM_SESSION_STRING"]
TOKEN_SECRET = os.environ["TELEGRAM_STREAM_TOKEN_SECRET"]  # MUST match Next.js's env var of the same name
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
# Render (and most PaaS hosts) inject PORT themselves and require the
# app to bind to it — that takes priority over LISTEN_PORT if both are
# somehow set. Falls back to 8088 for a plain VPS/systemd setup where
# neither is set.
LISTEN_PORT = int(os.environ.get("PORT") or os.environ.get("LISTEN_PORT", "8088"))
APP_ORIGIN = os.environ.get("APP_ORIGIN", "")  # e.g. https://learn.nexsecurity.example — for CORS + the webhook
SECURITY_WEBHOOK_SECRET = os.environ.get("SECURITY_WEBHOOK_SECRET", "")  # same var name/value as worker/wrangler.toml
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))  # 1 = Caddy/nginx directly in front

# Render's free plan puts a service to sleep after ~15 min without inbound
# traffic, and the next request then waits 30-60s for a cold start. Pinging
# our own public URL every 10 min keeps it awake. Render sets
# RENDER_EXTERNAL_URL itself; set KEEP_ALIVE=0 to turn this off.
KEEP_ALIVE = os.environ.get("KEEP_ALIVE", "1") != "0"
SELF_URL = os.environ.get("RENDER_EXTERNAL_URL", "")
REPORT_IP_MISMATCH = os.environ.get("REPORT_IP_MISMATCH", "1") != "0"

SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", str(8 * 3600)))  # comfortably over the longest class
CHUNK_CACHE_BYTES = int(os.environ.get("CHUNK_CACHE_MAX_MB", "256")) * 1024 * 1024
DOWNLOAD_CHUNK = 1024 * 1024  # Telegram MTProto part size for iter_download; must stay a power of 2, 4KiB-aligned
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "240"))  # per uid, generous (many Range requests/scrub)

sessions = core.SessionStore(ttl=SESSION_TTL_SECONDS)
chunk_cache = core.ChunkCache(CHUNK_CACHE_BYTES)
_rate_buckets: dict[str, tuple[int, float]] = {}

SUSPICIOUS_UA_RE = re.compile(
    r"curl|wget|python-requests|python-urllib|aiohttp|httpx|okhttp|libwww|aria2|yt-dlp|youtube-dl|ffmpeg|lavf|"
    r"internet download manager|\bidm\b|downloader|httrack|postman|insomnia|axios|node-fetch|go-http-client|java/|^$",
    re.I,
)

# ---------------------------------------------------------------------------
# Anti-download hardening (all can be tuned / switched off with env vars)
# ---------------------------------------------------------------------------
# Real <video> elements send "Sec-Fetch-Dest: video"; curl, IDM, wget, scripts,
# opening the URL in a tab ("document") and fetch() ("empty") do not.
REQUIRE_FETCH_DEST = os.environ.get("REQUIRE_FETCH_DEST", "1") != "0"
# The page that embeds the player must be ours (browser sends it automatically).
REQUIRE_REFERER = os.environ.get("REQUIRE_REFERER", "1") != "0"
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in ([APP_ORIGIN] + os.environ.get("EXTRA_ALLOWED_ORIGINS", "").split(",")) if o.strip()]
# A stolen/copied URL stops working once it's used from more than this many
# different networks (a student switching Wi-Fi <-> mobile data uses 1-2).
MAX_SESSION_IP_CHANGES = int(os.environ.get("MAX_SESSION_IP_CHANGES", "4"))
# Hard cap on one playback session's age; the player silently gets a new token.
SESSION_MAX_SECONDS = int(os.environ.get("SESSION_MAX_SECONDS", str(6 * 3600)))
# Limits per (user, video), see core.ViewerLimiter.
THROTTLE_DOWNLOADS = os.environ.get("THROTTLE_DOWNLOADS", "1") != "0"
limiter = core.ViewerLimiter(
    max_conns=int(os.environ.get("MAX_CONNS_PER_VIEWER", "4")),
    day_factor=float(os.environ.get("DAILY_BYTES_FACTOR", "6")),  # 0 = no daily cap
    rate_factor=float(os.environ.get("STREAM_RATE_FACTOR", "3")),
)
# Header the edge sets with the real client IP (Cloudflare: CF-Connecting-IP).
# Empty = try CF-Connecting-IP, then True-Client-IP, then X-Forwarded-For.
CLIENT_IP_HEADER = os.environ.get("CLIENT_IP_HEADER", "").strip()

_ip_headers_logged = False

# Tokens whose session we killed. Without this, a dropped session's token
# (valid for ~90 s after it was minted) could simply be redeemed again.
_revoked: dict = {}


def revoke(jti: str) -> None:
    sessions.drop(jti)
    _revoked[jti] = time.time() + 900


def request_ip(request: web.Request) -> str:
    global _ip_headers_logged
    h = request.headers
    preferred = (h.get(CLIENT_IP_HEADER) if CLIENT_IP_HEADER else None) or h.get("CF-Connecting-IP") or h.get("True-Client-IP")
    if not _ip_headers_logged:
        _ip_headers_logged = True
        log.info(
            "[info] client-ip headers seen (first request): X-Forwarded-For=%r CF-Connecting-IP=%r True-Client-IP=%r remote=%r",
            h.get("X-Forwarded-For"), h.get("CF-Connecting-IP"), h.get("True-Client-IP"), request.remote,
        )
    return core.client_ip(h.get("X-Forwarded-For"), request.remote, TRUSTED_PROXY_HOPS, preferred=preferred)


def not_a_player_request(request: web.Request) -> Optional[str]:
    """None if this looks like a <video> element on our own site; otherwise a
    short reason (for the log). Not unforgeable by a determined person, but it
    stops every ordinary download tool and 'open the URL / Save as' trick."""
    h = request.headers
    if REQUIRE_FETCH_DEST:
        dest = h.get("Sec-Fetch-Dest", "").lower()
        if dest not in ("video", "audio"):
            return f"Sec-Fetch-Dest={dest or 'missing'}"
    if REQUIRE_REFERER and ALLOWED_ORIGINS:
        ref = (h.get("Referer") or h.get("Origin") or "").rstrip("/")
        if not any(ref == o or ref.startswith(o + "/") for o in ALLOWED_ORIGINS):
            return f"Referer={ref[:80] or 'missing'}"
    return None


class _RedactTokens(logging.Filter):
    """aiohttp's access log prints the full URL, i.e. every playback token.
    Anyone who can read the logs could replay them, so blank them out."""

    _RE = re.compile(r'([?&]t=)[^\s&"]+')

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self._RE.sub(r"\1REDACTED", record.msg)
            if record.args:
                record.args = tuple(self._RE.sub(r"\1REDACTED", a) if isinstance(a, str) else a for a in record.args)
        except Exception:
            pass
        return True


logging.getLogger("aiohttp.access").addFilter(_RedactTokens())

client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)

# entity/message cache — avoids a get_messages round trip on every one of
# the dozens of Range requests one video generates. File references
# expire after a few hours; a fetch that hits FileReferenceExpiredError
# refreshes this entry and retries once.
_msg_cache: dict[tuple, tuple[object, float]] = {}
_MSG_CACHE_TTL = 3 * 3600


def rate_limited(key: str, limit: int = RATE_LIMIT_PER_MIN, window: float = 60.0) -> bool:
    now = time.time()
    count, reset_at = _rate_buckets.get(key, (0, now + window))
    if now > reset_at:
        count, reset_at = 0, now + window
    count += 1
    _rate_buckets[key] = (count, reset_at)
    return count > limit


_bg_tasks: set = set()


def fire_and_forget(coro) -> None:
    """Runs `coro` in the background so the viewer's first byte never waits
    on it (keeps a strong ref so the task isn't garbage-collected early)."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


async def keep_alive_loop():
    import aiohttp

    url = f"{SELF_URL.rstrip('/')}/healthz"
    while True:
        await asyncio.sleep(600)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    await r.read()
        except Exception as e:
            log.warning("keep-alive ping failed: %s", e)


async def report_suspicious(reason: str, aid: str, vid: str, uid: str, ip: str):
    if not APP_ORIGIN or not SECURITY_WEBHOOK_SECRET:
        return
    import aiohttp

    try:
        async with aiohttp.ClientSession() as s:
            # `async with` on the response + reading the body is what
            # releases the connection; without it aiohttp logs
            # "Unclosed connection" for every report.
            async with s.post(
                f"{APP_ORIGIN.rstrip('/')}/api/security/token-mismatch",
                json={"reason": reason, "aid": aid, "videoId": vid, "uid": uid, "ip": ip},
                headers={"X-Security-Webhook-Secret": SECURITY_WEBHOOK_SECRET},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                await r.read()
    except Exception as e:  # fire-and-forget — never let this break playback
        log.warning("suspicious-activity report failed: %s", e)


class SourceUnavailable(LookupError):
    """The Telegram source can't be played. `reason` is for OUR logs only
    (never sent to the browser); `status` is the HTTP status we answer with."""

    def __init__(self, reason: str, status: int = 404):
        super().__init__(reason)
        self.reason = reason
        self.status = status


async def _nearby_summary(entity, msg_id: int) -> str:
    """Best-effort: what are the messages around `msg_id`? When an admin
    pastes the wrong link this shows exactly which neighbouring id holds
    the video, so the fix is obvious from the log alone."""
    try:
        ids = [i for i in range(msg_id - 3, msg_id + 4) if i > 0 and i != msg_id]
        msgs = await client.get_messages(entity, ids=ids)
        parts = []
        for i, m in zip(ids, msgs):
            if m is None:
                parts.append(f"{i}=missing")
            elif m.document:
                parts.append(f"{i}=VIDEO/FILE")
            elif m.media:
                parts.append(f"{i}=other-media")
            else:
                parts.append(f"{i}=text")
        return ", ".join(parts)
    except Exception as e:  # diagnostics must never break playback
        return f"(could not inspect nearby messages: {type(e).__name__})"


async def resolve_message(sr: core.SourceRef):
    key = (sr.kind, sr.peer, sr.msg_id)
    cached = _msg_cache.get(key)
    if cached and time.time() - cached[1] < _MSG_CACHE_TTL:
        return cached[0]

    try:
        if sr.kind == "private":
            # Numeric internal channel id -> Telethon peer. The account this
            # client is logged in as MUST already be a member of the channel
            # (see README.md) or get_entity will fail.
            entity = await client.get_entity(int(f"-100{sr.peer}"))
        else:
            entity = await client.get_entity(sr.peer)
    except errors.FloodWaitError:
        raise
    except (ValueError, errors.RPCError) as e:
        raise SourceUnavailable(
            f"the Telegram account can't open this chat ({type(e).__name__}: {e}). "
            "Check the channel id in the link, and that the bot is added to the channel as an admin.",
            403,
        )

    try:
        msg = await client.get_messages(entity, ids=sr.msg_id)
    except errors.FloodWaitError:
        raise
    except errors.RPCError as e:
        raise SourceUnavailable(f"Telegram refused to return message {sr.msg_id} ({type(e).__name__}: {e}).", 403)

    title = getattr(entity, "title", None) or getattr(entity, "username", None) or sr.peer
    if msg is None:
        raise SourceUnavailable(
            f"message id {sr.msg_id} does not exist in chat {title!r} (deleted, or wrong id in the link). "
            f"Neighbouring messages: {await _nearby_summary(entity, sr.msg_id)}",
            404,
        )
    if msg.media is None:
        raise SourceUnavailable(
            f"message id {sr.msg_id} in chat {title!r} is a text-only message, not a video. "
            f"Neighbouring messages: {await _nearby_summary(entity, sr.msg_id)}",
            404,
        )
    if not msg.document:
        raise SourceUnavailable(
            f"message id {sr.msg_id} in chat {title!r} has media ({type(msg.media).__name__}) but no video file. "
            f"Neighbouring messages: {await _nearby_summary(entity, sr.msg_id)}",
            404,
        )
    _msg_cache[key] = (msg, time.time())
    return msg


def document_size(msg) -> int:
    doc = msg.media.document if hasattr(msg.media, "document") else None
    if isinstance(doc, Document):
        return doc.size
    if msg.file and msg.file.size:
        return msg.file.size
    raise LookupError("could not determine file size")


# --------------------------------------------------------------------------
# HTTP handlers
# --------------------------------------------------------------------------


def json_error(message: str, status: int) -> web.Response:
    return web.json_response({"error": message}, status=status)


def cors_headers() -> dict:
    # No credentials/cookies involved (auth is the `t=`/session token in
    # the query string, not a cookie), so a permissive ACAO is fine —
    # mirrors media-src/connect-src already being wide-open in
    # next.config.js for the same reason (see that file's comments).
    return {"Access-Control-Allow-Origin": APP_ORIGIN or "*", "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS"}


async def handle_options(request: web.Request) -> web.Response:
    return web.Response(headers=cors_headers())


async def handle_stream(request: web.Request) -> web.StreamResponse:
    t0 = time.monotonic()
    video_id = request.match_info["video_id"]
    token = request.query.get("t")
    ip = request_ip(request)
    ip_hash = core.hash_for_token(ip)

    if not token:
        log.warning("[deny] no token, video_id=%s ip=%s", video_id, ip)
        return json_error("Access denied.", 403)

    why = not_a_player_request(request)
    if why:
        log.warning("[deny] not a player request (%s), video_id=%s ip=%s ua=%r", why, video_id, ip, request.headers.get("User-Agent", "")[:80])
        return json_error("Access denied.", 403)

    jti = core.hash_for_token(token)
    if _revoked.get(jti, 0) > time.time():
        log.warning("[deny] revoked token presented again, video_id=%s ip=%s", video_id, ip)
        return json_error("Access denied.", 403)
    sess = sessions.get(jti)

    if sess is None:
        # First time this token is seen — it must decrypt, match this
        # video id, still be inside its mint window, AND come from the
        # IP it was minted for.
        payload = core.decrypt_payload(token, TOKEN_SECRET)
        if not payload:
            log.warning(
                "[deny] token failed to decrypt (TELEGRAM_STREAM_TOKEN_SECRET mismatch, or a "
                "corrupted/truncated `t=` param), video_id=%s ip=%s",
                video_id, ip,
            )
            return json_error("Access denied.", 403)
        if payload.get("vid") != video_id:
            log.warning(
                "[deny] token vid mismatch: token was for %s, request was for %s, ip=%s",
                payload.get("vid"), video_id, ip,
            )
            return json_error("Access denied.", 403)
        if payload.get("exp", 0) < time.time():
            log.warning(
                "[deny] token expired %.0fs ago, video_id=%s ip=%s",
                time.time() - payload.get("exp", 0), video_id, ip,
            )
            return json_error("Access denied.", 403)
        if payload.get("ip") != ip_hash:
            # Soft check ONLY, deliberately not a 403 here: this token was
            # minted by Next.js on Vercel's infrastructure and is being
            # redeemed against Render's — two entirely separate networks,
            # so "the client's IP" isn't guaranteed to come out identical
            # on both sides even for the SAME browser (IPv4/IPv6 Happy
            # Eyeballs picking differently per destination, some mobile
            # carriers NAT-ing per-destination, etc. — all seen in
            # practice, not hypothetical). The token's own encryption +
            # expiry + video-id match, plus the device-concurrency-limit
            # and rate limit below, are what's actually load-bearing here;
            # this is now only signal for the security-review webhook.
            log.info(
                "[info] ip differs between mint (Vercel) and redeem (here): token ip_hash=%s vs this ip_hash=%s "
                "(raw ip seen here=%s) — allowed anyway, see the comment above this line. video_id=%s",
                payload.get("ip"), ip_hash, ip, video_id,
            )
            if REPORT_IP_MISMATCH:
                fire_and_forget(report_suspicious("ip_mismatch", payload.get("aid", ""), video_id, payload.get("uid", ""), ip))
        source_ref = payload.get("sr", "")
        uid = payload.get("uid", "")
        aid = payload.get("aid", "")
        sess = sessions.register(jti, ip_hash)
        sess.source_ref = source_ref  # type: ignore[attr-defined]
        sess.uid = uid  # type: ignore[attr-defined]
        sess.aid = aid  # type: ignore[attr-defined]
    else:
        # Established session. Two hard limits so a copied URL can't be used
        # for long, or from somewhere else:
        #  - absolute age (never slides), the player just fetches a new token;
        #  - the client IP may change only a few times (Wi-Fi <-> mobile data
        #    does that legitimately; two people using one URL flips it back
        #    and forth constantly and trips the limit within seconds).
        if time.time() - sess.born > SESSION_MAX_SECONDS:
            revoke(jti)
            log.info("[info] session older than %ss, dropped (player will get a new token). video_id=%s", SESSION_MAX_SECONDS, video_id)
            return json_error("Access denied.", 403)
        sessions.register(jti, ip_hash)  # slides expiry, re-binds IP and counts a change
        if sess.ip_changes > MAX_SESSION_IP_CHANGES:
            log.warning(
                "[deny] playback URL used from too many networks (%d changes), session dropped. video_id=%s ip=%s",
                sess.ip_changes, video_id, ip,
            )
            fire_and_forget(report_suspicious("ip_mismatch", getattr(sess, "aid", ""), video_id, getattr(sess, "uid", ""), ip))
            revoke(jti)
            return json_error("Access denied.", 403)
        source_ref = sess.source_ref  # type: ignore[attr-defined]
        uid = sess.uid  # type: ignore[attr-defined]

    ua = request.headers.get("User-Agent", "")
    if SUSPICIOUS_UA_RE.search(ua):
        log.warning("[deny] suspicious User-Agent %r, video_id=%s ip=%s", ua, video_id, ip)
        fire_and_forget(report_suspicious("bot_signature", getattr(sess, "aid", ""), video_id, uid, ip))
        return json_error("Access denied.", 403)

    if rate_limited(uid):
        log.warning("[deny] rate limit hit for uid=%s, video_id=%s", uid, video_id)
        return json_error("Too many requests.", 429)

    parsed_ref = core.parse_source_ref(source_ref)
    if not parsed_ref:
        log.error("[error] source_ref %r doesn't match expected grammar, video_id=%s", source_ref, video_id)
        return json_error("Playback unavailable.", 500)

    try:
        msg = await resolve_message(parsed_ref)
        size = document_size(msg)
        t_resolved = time.monotonic()
    except SourceUnavailable as e:
        log.error("[error] can't play source_ref=%r (video_id=%s): %s", source_ref, video_id, e.reason)
        return json_error("Playback unavailable.", e.status)
    except LookupError as e:
        log.error("[error] couldn't resolve Telegram message for source_ref=%r: %s", source_ref, e)
        return json_error("Playback unavailable.", 404)
    except errors.FloodWaitError as e:
        log.warning("Telegram flood-wait %ss while resolving %s", e.seconds, source_ref)
        return json_error("Server is busy, try again shortly.", 503)

    duration = getattr(getattr(msg, "file", None), "duration", None)
    params = limiter.params(size, duration) if THROTTLE_DOWNLOADS else None
    viewer = limiter.get((uid, video_id), params[1] if params else 0)
    if viewer.conns >= limiter.max_conns:
        log.warning("[deny] too many parallel connections (%d) for uid=%s video_id=%s", viewer.conns, uid, video_id)
        return json_error("Too many requests.", 429)
    if limiter.day_over(viewer, size):
        log.warning("[deny] 24h data limit reached for uid=%s video_id=%s", uid, video_id)
        return json_error("Too many requests.", 429)

    async def pace(n: int) -> None:
        wait = limiter.take(viewer, n, size, params)
        if wait > 0:
            await asyncio.sleep(wait)

    try:
        start, end = core.parse_range(request.headers.get("Range"), size) or (0, size - 1)
    except core.RangeNotSatisfiable:
        return web.Response(status=416, headers={"Content-Range": f"bytes */{size}", **cors_headers()})

    is_partial = request.headers.get("Range") is not None
    length = end - start + 1
    headers = {
        "Content-Type": "video/mp4",
        "Accept-Ranges": "bytes",
        "Content-Length": str(length),
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": "inline",
        **cors_headers(),
    }
    if is_partial:
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"

    resp = web.StreamResponse(status=206 if is_partial else 200, headers=headers)
    await resp.prepare(request)

    sess.conns += 1
    viewer.conns += 1
    try:
        await stream_range(msg, start, end, resp, perf=(t0, t_resolved, video_id), pace=pace)
    except (ConnectionResetError, asyncio.CancelledError):
        pass  # viewer paused/seeked/closed the tab — not an error
    except core.DailyLimitExceeded:
        log.warning("[deny] 24h data limit reached mid-stream for uid=%s video_id=%s", uid, video_id)
    except errors.FileReferenceExpiredError:
        # File reference went stale mid-stream (long-running server,
        # rare) — drop the cache entry so the NEXT request re-resolves.
        _msg_cache.pop((parsed_ref.kind, parsed_ref.peer, parsed_ref.msg_id), None)
    finally:
        sess.conns = max(0, sess.conns - 1)
        viewer.conns = max(0, viewer.conns - 1)
    return resp


# How many 1MB chunks are being fetched from Telegram AT THE SAME TIME.
# The old code pulled them strictly one after another (one request in
# flight), so download speed was capped at roughly 1MB / Telegram-round-trip
# (a few MB/s) no matter how fast the connection was, and the first seconds
# of a video felt slow. Fetching several chunks concurrently over the same
# MTProto connection hides that round-trip time, so playback starts sooner
# and keeps its buffer full. Memory per viewer is about this many MB.
PREFETCH_CHUNKS = int(os.environ.get("PREFETCH_CHUNKS", "4"))
# Until the first bytes have reached the browser only this many chunks are
# fetched together, so the first chunk isn't slowed down by its siblings.
STARTUP_CHUNKS = int(os.environ.get("STARTUP_CHUNKS", "2"))


async def fetch_chunk(msg, offset: int) -> bytes:
    """One DOWNLOAD_CHUNK-sized part of the file starting at `offset`
    (must be DOWNLOAD_CHUNK-aligned). Served from the chunk cache when
    possible; b'' means the offset is past the end of the file."""
    key = (msg.chat_id, msg.id, offset)
    cached = chunk_cache.get(key)
    if cached is not None:
        return cached
    it = client.iter_download(msg.media, offset=offset, request_size=DOWNLOAD_CHUNK, limit=1)
    data = b""
    try:
        async for part in it:
            data = bytes(part)
            break
    finally:
        closer = getattr(it, "close", None)
        if closer is not None:
            try:
                await closer()
            except Exception:
                pass
    if data:
        chunk_cache.put(key, data)
    return data


async def stream_range(msg, start: int, end: int, resp: web.StreamResponse, perf: Optional[tuple] = None, pace=None):
    """Downloads [start, end] (inclusive) from Telegram and writes it to
    the HTTP response as it arrives. MTProto downloads happen in aligned
    chunks, so `start` is rounded down to a DOWNLOAD_CHUNK boundary and the
    extra leading bytes are trimmed off the first chunk.

    Up to PREFETCH_CHUNKS chunks are fetched concurrently and written in
    order (see the comment above). `perf` = (t0, t_resolved, video_id) is
    only used to log how long the first byte took. `pace(n)` (optional) is
    awaited before each write; it enforces the per-viewer speed limit.
    """
    aligned_start = (start // DOWNLOAD_CHUNK) * DOWNLOAD_CHUNK
    skip = start - aligned_start
    remaining = end - start + 1
    last_offset = (end // DOWNLOAD_CHUNK) * DOWNLOAD_CHUNK
    offsets = iter(range(aligned_start, last_offset + 1, DOWNLOAD_CHUNK))

    pending: deque = deque()
    window = max(1, min(STARTUP_CHUNKS, PREFETCH_CHUNKS))
    wrote_first = False

    def schedule():
        while len(pending) < window:
            off = next(offsets, None)
            if off is None:
                return
            pending.append(asyncio.create_task(fetch_chunk(msg, off)))

    try:
        schedule()
        while pending and remaining > 0:
            data = await pending.popleft()
            if not data:
                break
            piece = data[skip:] if skip else data
            skip = 0
            n = min(len(piece), remaining)
            if n > 0:
                if pace is not None:
                    await pace(n)
                await resp.write(piece if n == len(piece) else piece[:n])
                remaining -= n
                if not wrote_first:
                    wrote_first = True
                    window = max(1, PREFETCH_CHUNKS)  # now fill the whole read-ahead window
                    if perf:
                        t0, t_res, vid = perf
                        log.info(
                            "[perf] video_id=%s range=%d-%d first_byte=%.2fs (resolve %.2fs, telegram %.2fs)",
                            vid, start, end, time.monotonic() - t0, t_res - t0, time.monotonic() - t_res,
                        )
            schedule()
    finally:
        tasks = list(pending)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "connected": client.is_connected(), "sessions": len(sessions)})


async def periodic_purge():
    while True:
        await asyncio.sleep(300)
        n = sessions.purge()
        if n:
            log.info("purged %d expired sessions", n)
        limiter.purge()
        now = time.time()
        for k in [k for k, v in _revoked.items() if v < now]:
            del _revoked[k]



# --------------------------------------------------------------------------
# /scan: admin-only helper that lists which message ids in a channel really
# hold a video/file, so the right link can be copied without guessing.
# Disabled unless the SCAN_KEY env var is set. Remove SCAN_KEY when done.
# --------------------------------------------------------------------------

SCAN_KEY = os.environ.get("SCAN_KEY", "")
SCAN_MAX_IDS = 300


def _media_kind(m) -> str:
    if m.video:
        return "video"
    if m.document:
        return "file"
    if m.photo:
        return "photo"
    return "other-media"


async def handle_scan(request: web.Request) -> web.Response:
    # Looks like a missing route when disabled, so it can't be probed.
    if not SCAN_KEY:
        return web.Response(status=404, text="Not Found")
    given = request.query.get("key", "")
    if not hmac.compare_digest(given.encode(), SCAN_KEY.encode()):
        return web.Response(status=404, text="Not Found")

    chat = request.query.get("chat", "").strip().strip("/")
    # chat = "c/4407121895" (private channel) or "username" (public)
    sr = core.parse_source_ref(f"{chat}/1")
    if not sr:
        return web.json_response({"error": "chat must look like c/4407121895 or a public username"}, status=400)
    try:
        start = max(1, int(request.query.get("from", "1")))
        end = int(request.query.get("to", str(start + 199)))
    except ValueError:
        return web.json_response({"error": "from/to must be numbers"}, status=400)
    end = min(end, start + SCAN_MAX_IDS - 1)
    if end < start:
        return web.json_response({"error": "to must be >= from"}, status=400)

    try:
        entity = await client.get_entity(int(f"-100{sr.peer}") if sr.kind == "private" else sr.peer)
    except (ValueError, errors.RPCError) as e:
        return web.json_response({"error": f"bot can't open this chat: {type(e).__name__}: {e}"}, status=403)

    ids = list(range(start, end + 1))
    found, counts = [], {"missing": 0, "text_or_service": 0}
    for i in range(0, len(ids), 100):
        batch = ids[i : i + 100]
        try:
            msgs = await client.get_messages(entity, ids=batch)
        except errors.RPCError as e:
            return web.json_response({"error": f"Telegram refused: {type(e).__name__}: {e}"}, status=502)
        for mid, m in zip(batch, msgs):
            if m is None:
                counts["missing"] += 1
            elif not m.media:
                counts["text_or_service"] += 1
            else:
                doc = m.document
                attrs = {type(a).__name__: a for a in (doc.attributes if doc else [])}
                duration = getattr(attrs.get("DocumentAttributeVideo"), "duration", None)
                fname = getattr(attrs.get("DocumentAttributeFilename"), "file_name", None)
                found.append(
                    {
                        "id": mid,
                        "type": _media_kind(m),
                        "name": fname,
                        "size_mb": round(doc.size / 1048576, 1) if doc else None,
                        "duration_s": int(duration) if duration else None,
                        "caption": (m.message or "")[:60] or None,
                        "link": f"https://t.me/c/{sr.peer}/{mid}" if sr.kind == "private" else f"https://t.me/{sr.peer}/{mid}",
                    }
                )

    body = {
        "chat": getattr(entity, "title", None) or str(sr.peer),
        "scanned": f"{start}-{end}",
        "counts": {**counts, "with_media": len(found)},
        "media_messages": found,
        "next": f"scan?chat={chat}&from={end + 1}&key=...",
    }
    return web.Response(text=json.dumps(body, indent=2, ensure_ascii=False), content_type="application/json")


async def on_startup(app: web.Application):
    await client.start()
    me = await client.get_me()
    log.info("Telegram client connected as %s", getattr(me, "username", None) or me.id)
    try:
        import cryptg  # noqa: F401

        log.info("cryptg is installed: fast AES for Telegram downloads")
    except ImportError:
        log.warning("cryptg is NOT installed: Telegram downloads use slower AES (see README, speed section)")
    app["purge_task"] = asyncio.create_task(periodic_purge())
    if KEEP_ALIVE and SELF_URL:
        app["keepalive_task"] = asyncio.create_task(keep_alive_loop())
        log.info("keep-alive enabled: pinging %s/healthz every 10 min", SELF_URL.rstrip("/"))


async def on_cleanup(app: web.Application):
    app["purge_task"].cancel()
    if "keepalive_task" in app:
        app["keepalive_task"].cancel()
    await client.disconnect()


def build_app() -> web.Application:
    app = web.Application(client_max_size=0)  # streaming responses only; no request bodies to bound
    # add_get() already registers HEAD for the same handler automatically
    # (aiohttp does this internally) — an explicit add_head() call here
    # would try to register the exact same route twice and crash at
    # startup with "Added route will never be executed".
    app.router.add_get("/tg/{video_id}", handle_stream)
    app.router.add_route("OPTIONS", "/tg/{video_id}", handle_options)
    app.router.add_get("/healthz", handle_health)
    app.router.add_get("/scan", handle_scan)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host=LISTEN_HOST, port=LISTEN_PORT)
