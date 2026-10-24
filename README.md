# tg-stream — Telegram-hosted classes for NexSecurity

Lets an admin post a class video as a message in a Telegram channel
(public or private) and paste its link into `/admin/videos` — provider
**"Telegram channel"** — instead of uploading to Bunny. Playback goes
through this server, never through Telegram's own app/website, and is
gated by the exact same login → board-access → device-limit checks every
other provider already goes through (see the long comments in
`../app/api/video/[id]/telegram-token/route.ts`).

This is a genuinely different trust model from Bunny/Cloudflare: those
are paid CDNs whose entire job is serving video at scale. Telegram is
not that, and this relay leans on one account's normal API access to
read messages — read the **Limits & risk** section below before
depending on this for real classes.

## How it fits together

```
Browser  ──POST /api/video/:id/telegram-token──▶  Next.js (Vercel)
   │        (real auth/board/device-limit checks — same as every provider)
   │◀── short-lived encrypted token ──────────────────┘
   │
   └──GET tg.example.com/tg/:id?t=<token>──▶  tg-stream/server.py (this)
                                                   │
                                                   ▼
                                            Telegram (MTProto, via Telethon)
```

`server.py` decrypts the token itself (shared secret with Next.js —
`TELEGRAM_STREAM_TOKEN_SECRET`), so it never calls Supabase. On the
first request for a token it establishes a sliding in-memory session
(see `core.SessionStore`) so the dozens of `Range` requests a 2-5 hour
`<video>` element makes while scrubbing don't each need a fresh token —
only the very first request per player-load needs a still-fresh one; the
session's own IP-bind is re-checked on every single request after that.

## One-time setup

1. **Get Telegram API credentials**: https://my.telegram.org/apps →
   create an app → note the `api_id` and `api_hash`.
2. **Create the account that will read the channel.** Recommended: a
   **bot** via [@BotFather](https://t.me/BotFather), added to each
   private channel as an **admin** with "Read Message History" enabled
   (public channels don't need this — anyone/anything can read them).
   Telethon downloads over raw MTProto even for a bot, so — unlike the
   plain HTTP Bot API — it is **not** capped at 20MB. See **Limits &
   risk** for why a bot beats a personal account here.
3. On the machine that will run this (or any machine, once):
   ```
   pip install -r requirements.txt
   python3 gen_session.py
   ```
   Paste the `api_id`/`api_hash` from step 1 and, when asked, the bot
   token from step 2 (leave blank to log in as a personal account
   instead). It prints `TELEGRAM_SESSION_STRING` — copy it somewhere
   safe; it's as sensitive as a password.
4. **Provision a small VPS** (1 vCPU / 1GB RAM is plenty for 35
   concurrent viewers — this only relays bytes, it doesn't transcode)
   with a DNS subdomain, e.g. `tg.yourdomain.com`, pointed at it.
5. Copy this `tg-stream/` folder to the VPS, then:
   ```
   python3 -m venv venv && venv/bin/pip install -r requirements.txt
   cp .env.example .env   # see below — fill in every value
   ```
6. Put Caddy (or nginx) in front for TLS — `Caddyfile.example` here is
   a complete working config for Caddy; point it at
   `127.0.0.1:8088` (or whatever `LISTEN_PORT` you set).
7. Install as a service: `tg-stream.service.example` → copy to
   `/etc/systemd/system/tg-stream.service` (edit the paths/user first),
   then `systemctl enable --now tg-stream`.
8. **On the Next.js side** (Vercel → Project → Settings → Environment
   Variables, every environment that actually serves Telegram video):
   - `TELEGRAM_STREAM_TOKEN_SECRET` — a long random string, the exact
     same value as this server's env var of the same name.
   - `NEXT_PUBLIC_TG_STREAM_WORKER_BASE` — e.g. `https://tg.yourdomain.com`
     (no trailing slash). Public on purpose — the browser builds the
     playback URL directly against it, same reasoning as the existing
     `NEXT_PUBLIC_STREAM_WORKER_BASE` var (see `../worker/README.md`).
     No CSP change needed for this one: `media-src` in `next.config.js`
     already allows any `https:` origin (it's what lets the `mp4`
     provider point anywhere already).
9. Redeploy the Next.js app so it picks up the new env vars.

## `.env` for this server

```
TELEGRAM_API_ID=...
TELEGRAM_API_HASH=...
TELEGRAM_SESSION_STRING=...            # from gen_session.py
TELEGRAM_STREAM_TOKEN_SECRET=...       # SAME value as the Vercel env var
LISTEN_HOST=127.0.0.1
LISTEN_PORT=8088
APP_ORIGIN=https://learn.yourdomain.com     # for the security webhook below
SECURITY_WEBHOOK_SECRET=...             # SAME value as the existing Vercel var (worker/wrangler.toml already uses this name)
TRUSTED_PROXY_HOPS=1                    # 1 if Caddy/nginx sits directly in front
SESSION_TTL_SECONDS=28800               # 8h — comfortably over any one class
CHUNK_CACHE_MAX_MB=256
RATE_LIMIT_PER_MIN=240
```

## Adding a class in `/admin/videos`

1. In Telegram, open the class video inside the channel → **⋮ → Copy
   Message Link**. For a private channel this looks like
   `https://t.me/c/1234567890/123`; for a public one,
   `https://t.me/mychannel/123`.
2. In `/admin/videos`, pick **Telegram channel**, paste that link, save.

That's it — no need to hand-construct `source_ref`; the admin form
parses either link shape itself (`app/admin/videos/page.tsx`'s
`parseTelegramRef`).

## Limits & risk (read this before relying on it for real classes)

- **~35 students / ~100 classes / 2-5h videos** is comfortably inside
  what one small VPS handles — this server only relays bytes, it never
  transcodes or stores full files (an LRU byte-chunk cache, capped by
  `CHUNK_CACHE_MAX_MB`, is the only thing it keeps in memory). Bandwidth
  is the real cost: a 5h 1080p class is roughly 3-5GB; several students
  watching concurrently is simple multiplication from there — budget
  your VPS's network accordingly (most providers meter or cap monthly
  transfer).
- **Telegram rate limits.** Telegram enforces `FLOOD_WAIT` on excessive
  requests from one account; `server.py` catches this and returns a 503
  rather than crashing, but if it starts happening under real load,
  slow down `RATE_LIMIT_PER_MIN` or split classes across more than one
  bot/session.
- **This is one account's access, with no SLA.** If the bot is removed
  from a channel, its session revoked, or Telegram rate-limits it
  broadly, every class relayed through it goes down until fixed —
  unlike Bunny, there's no redundancy here by default.
- **Single point of failure / single server.** No built-in horizontal
  scaling like the Cloudflare Worker gets for `m3u8`. For this
  audience size that's fine; if it ever needs to grow well past ~35
  concurrent viewers, look at running more than one `tg-stream`
  instance (each with its own bot/session) behind a load balancer.
- **A personal account instead of a bot** is discouraged: Telegram's
  Terms of Service restrict automated use of a regular user account,
  and unusual sustained download volume from one is a plausible flag
  vector; use it only if a channel genuinely can't have a bot admin
  added to it, and treat the account as expendable.
- **This is for content you/your organization actually has the right
  to redistribute this way** — same as every other provider in this
  app.

## What this intentionally does NOT change

- Bunny, YouTube, mp4, and m3u8 providers — completely untouched, this
  is a fifth, independent code path.
- The Cloudflare Worker (`../worker/`) — a different secret
  (`TELEGRAM_STREAM_TOKEN_SECRET` vs. `STREAM_TOKEN_SECRET`), a
  different server, no shared trust between the two.
- The admin panel's board/access model — a Telegram-provider class is
  attached to a board and gated by `canAccessBoard` exactly like every
  other class.
"# NexTG-Stream_Bot" 

## Start-up speed (time until the first frame)

- `KEEP_ALIVE` (default on): on Render the service pings its own `/healthz` every 10 min so the free plan never sleeps (a cold start is 30-60 s). Set `KEEP_ALIVE=0` to disable.
- Security reports to the website no longer delay the first byte (they run in the background). `REPORT_IP_MISMATCH=0` turns the Vercel-vs-Render IP-difference report off entirely.
- Best results: Render region closest to the viewers (Singapore for Bangladesh), and videos saved with the moov atom at the front: `ffmpeg -i in.mp4 -c copy -movflags +faststart out.mp4` before posting to Telegram.

## Finding the right message link (`/scan`)

Set `SCAN_KEY` (any long random string) in Render, redeploy, then open:

`https://<your-bot>.onrender.com/scan?chat=c/4407121895&from=1&to=200&key=<SCAN_KEY>`

It lists every message id in that range that holds a video/file (name, size, duration, ready-made link). Use `from`/`to` to page (max 300 ids per call). **Delete `SCAN_KEY` afterwards** — the endpoint then disappears (404).

## Playback speed

- Chunks are now fetched from Telegram **in parallel** (`PREFETCH_CHUNKS`, default 4; `STARTUP_CHUNKS`, default 2, applies until the first bytes are sent). Before, one 1MB request was in flight at a time.
- Every request logs `[perf] ... first_byte=…s (resolve …s, telegram …s)` so you can see where time goes: `resolve` = finding the message, `telegram` = getting the first chunk.
- `Dockerfile` installs `cryptg` (fast AES) when a wheel is available. The startup log says whether it is active.
- Biggest remaining factors (outside the code): Render region close to viewers (Singapore for Bangladesh), and MP4s with the index at the front: `ffmpeg -i in.mp4 -c copy -movflags +faststart out.mp4`.
