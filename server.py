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
import logging
import os
import re
import time
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

SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", str(8 * 3600)))  # comfortably over the longest class
CHUNK_CACHE_BYTES = int(os.environ.get("CHUNK_CACHE_MAX_MB", "256")) * 1024 * 1024
DOWNLOAD_CHUNK = 1024 * 1024  # Telegram MTProto part size for iter_download; must stay a power of 2, 4KiB-aligned
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "240"))  # per uid, generous (many Range requests/scrub)

sessions = core.SessionStore(ttl=SESSION_TTL_SECONDS)
chunk_cache = core.ChunkCache(CHUNK_CACHE_BYTES)
_rate_buckets: dict[str, tuple[int, float]] = {}

SUSPICIOUS_UA_RE = re.compile(r"curl|wget|python-requests|okhttp|libwww|aria2|yt-dlp|^$", re.I)

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
    video_id = request.match_info["video_id"]
    token = request.query.get("t")
    ip = core.client_ip(request.headers.get("X-Forwarded-For"), request.remote, TRUSTED_PROXY_HOPS)
    ip_hash = core.hash_for_token(ip)

    if not token:
        log.warning("[deny] no token, video_id=%s ip=%s", video_id, ip)
        return json_error("Access denied.", 403)

    jti = core.hash_for_token(token)
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
            await report_suspicious("ip_mismatch", payload.get("aid", ""), video_id, payload.get("uid", ""), ip)
        source_ref = payload.get("sr", "")
        uid = payload.get("uid", "")
        aid = payload.get("aid", "")
        sess = sessions.register(jti, ip_hash)
        sess.source_ref = source_ref  # type: ignore[attr-defined]
        sess.uid = uid  # type: ignore[attr-defined]
        sess.aid = aid  # type: ignore[attr-defined]
    else:
        # Established session — re-verify IP on every single request
        # (this is what stops a copied URL from working off-network,
        # same guarantee the Cloudflare Worker gives 'm3u8'), and slide
        # the session's expiry forward.
        if sess.ip != ip_hash:
            # Same reasoning as the mint-time check above — logged, not
            # blocked. Re-bind the session to whichever IP shows up most
            # recently rather than leaving it pinned to the first one.
            log.info(
                "[info] established session's ip_hash changed: was %s, now %s (raw ip=%s) — allowed. video_id=%s",
                sess.ip, ip_hash, ip, video_id,
            )
        sessions.register(jti, ip_hash)  # re-binds sess.ip to the current value too
        source_ref = sess.source_ref  # type: ignore[attr-defined]
        uid = sess.uid  # type: ignore[attr-defined]

    ua = request.headers.get("User-Agent", "")
    if SUSPICIOUS_UA_RE.search(ua):
        log.warning("[deny] suspicious User-Agent %r, video_id=%s ip=%s", ua, video_id, ip)
        await report_suspicious("bot_signature", getattr(sess, "aid", ""), video_id, uid, ip)
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
    except SourceUnavailable as e:
        log.error("[error] can't play source_ref=%r (video_id=%s): %s", source_ref, video_id, e.reason)
        return json_error("Playback unavailable.", e.status)
    except LookupError as e:
        log.error("[error] couldn't resolve Telegram message for source_ref=%r: %s", source_ref, e)
        return json_error("Playback unavailable.", 404)
    except errors.FloodWaitError as e:
        log.warning("Telegram flood-wait %ss while resolving %s", e.seconds, source_ref)
        return json_error("Server is busy, try again shortly.", 503)

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
        **cors_headers(),
    }
    if is_partial:
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"

    resp = web.StreamResponse(status=206 if is_partial else 200, headers=headers)
    await resp.prepare(request)

    sess.conns += 1
    try:
        await stream_range(msg, start, end, resp)
    except (ConnectionResetError, asyncio.CancelledError):
        pass  # viewer paused/seeked/closed the tab — not an error
    except errors.FileReferenceExpiredError:
        # File reference went stale mid-stream (long-running server,
        # rare) — drop the cache entry so the NEXT request re-resolves.
        _msg_cache.pop((parsed_ref.kind, parsed_ref.peer, parsed_ref.msg_id), None)
    finally:
        sess.conns = max(0, sess.conns - 1)
    return resp


# How many chunks to keep downloaded-but-not-yet-sent-to-the-browser at
# once. This is the actual fix for the stutter: without it, each loop
# iteration does "await download, THEN await send" strictly back to
# back, so every network hiccup on the Telegram side shows up directly
# as a stall in the browser. With a small read-ahead buffer, the
# downloader keeps pulling the NEXT chunk from Telegram while the
# CURRENT one is still being flushed to the browser's socket, so a
# brief slowdown on one side gets absorbed instead of becoming a visible
# stutter. Each chunk is DOWNLOAD_CHUNK bytes (1MB), so 4 is a ~4MB
# read-ahead window — enough to smooth normal jitter without holding a
# large amount of memory per concurrent viewer (this multiplies by
# however many Range connections are open at once).
PREFETCH_CHUNKS = int(os.environ.get("PREFETCH_CHUNKS", "4"))


async def stream_range(msg, start: int, end: int, resp: web.StreamResponse):
    """Downloads [start, end] (inclusive) from Telegram and writes it to
    the HTTP response as it arrives. Telegram/MTProto downloads must
    happen in 4096-byte-aligned chunks; we round `start` down to the
    nearest DOWNLOAD_CHUNK boundary ourselves and trim the extra leading
    bytes off the first yielded chunk, rather than relying on a specific
    Telethon version's own offset-rounding behavior.

    Downloading and writing-to-the-browser run as two separate
    concurrent tasks joined by a small bounded queue (see
    PREFETCH_CHUNKS above), instead of one strictly alternating loop —
    that overlap is what actually smooths out playback stutter; it is
    not just a buffering cosmetic.
    """
    aligned_start = (start // DOWNLOAD_CHUNK) * DOWNLOAD_CHUNK
    to_skip = start - aligned_start
    remaining_total = end - start + 1

    # Serve straight from cache with no network round trip at all when
    # every needed chunk is already there (a rewind, or a second student
    # a few seconds behind the first).
    cache_key0 = (msg.chat_id, msg.id, aligned_start)
    cached0 = chunk_cache.get(cache_key0)
    if cached0 is not None:
        piece = cached0[to_skip:]
        write_len = min(len(piece), remaining_total)
        await resp.write(piece[:write_len])
        remaining_total -= write_len
        if remaining_total <= 0:
            return
        aligned_start += DOWNLOAD_CHUNK
        to_skip = 0

    queue: asyncio.Queue = asyncio.Queue(maxsize=PREFETCH_CHUNKS)
    SENTINEL = object()

    async def downloader():
        try:
            async for chunk in client.iter_download(msg.media, offset=aligned_start, request_size=DOWNLOAD_CHUNK):
                await queue.put(bytes(chunk))
        except Exception as e:  # surfaced to the writer loop below via the queue
            await queue.put(e)
        finally:
            await queue.put(SENTINEL)

    dl_task = asyncio.create_task(downloader())
    try:
        offset = aligned_start
        remaining = remaining_total
        skip = to_skip
        while remaining > 0:
            item = await queue.get()
            if item is SENTINEL:
                break
            if isinstance(item, Exception):
                raise item
            chunk_bytes: bytes = item
            chunk_cache.put((msg.chat_id, msg.id, offset), chunk_bytes)
            piece = chunk_bytes[skip:] if skip else chunk_bytes
            skip = 0
            write_len = min(len(piece), remaining)
            if write_len > 0:
                await resp.write(piece[:write_len])
                remaining -= write_len
            offset += len(chunk_bytes)
    finally:
        dl_task.cancel()
        try:
            await dl_task
        except (asyncio.CancelledError, Exception):
            pass


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "connected": client.is_connected(), "sessions": len(sessions)})


async def periodic_purge():
    while True:
        await asyncio.sleep(300)
        n = sessions.purge()
        if n:
            log.info("purged %d expired sessions", n)


async def on_startup(app: web.Application):
    await client.start()
    me = await client.get_me()
    log.info("Telegram client connected as %s", getattr(me, "username", None) or me.id)
    app["purge_task"] = asyncio.create_task(periodic_purge())


async def on_cleanup(app: web.Application):
    app["purge_task"].cancel()
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
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host=LISTEN_HOST, port=LISTEN_PORT)
