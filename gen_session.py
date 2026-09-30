"""
One-time interactive login. Run this on your OWN machine (not the
server, though it can be the same box) to produce
TELEGRAM_SESSION_STRING.

    python3 gen_session.py

It asks for your phone number, then the login code Telegram sends you
(and your 2FA password, if you have one set). Prints a long string —
paste that into the server's TELEGRAM_SESSION_STRING env var and never
share it: it is equivalent to being logged into this Telegram account
from a new device, with no expiry until you revoke it (Telegram app →
Settings → Devices).

This account (whichever you pick below) MUST already be a member of
every private channel you plan to add videos from — get_entity/
get_messages in server.py can't resolve a channel this account hasn't
joined.

Two login options:
  1. Bot account (RECOMMENDED) — create one via @BotFather, add it to
     each private channel as an admin with "Read Message History".
     Telethon talks raw MTProto even for a bot, so — unlike the plain
     HTTP Bot API — it is NOT limited to 20MB downloads, and a bot
     carries none of the "automated user account" Terms-of-Service risk
     a personal account does. This is the safer default for 35+ students
     hitting it regularly.
  2. Personal/user account — only needed if you must stream from a
     channel you can't make this bot an admin of. Real risk of the
     account being rate-limited or flagged for unusual automated
     download volume; see tg-stream/README.md.
"""
import asyncio
import os

from telethon import TelegramClient
from telethon.sessions import StringSession


async def main():
    api_id = int(input("TELEGRAM_API_ID (from https://my.telegram.org/apps): ").strip())
    api_hash = input("TELEGRAM_API_HASH: ").strip()
    bot_token = input("Bot token (leave blank to log in as a personal account instead): ").strip()

    client = TelegramClient(StringSession(), api_id, api_hash)
    if bot_token:
        await client.start(bot_token=bot_token)
    else:
        await client.start()

    me = await client.get_me()
    print(f"\nLogged in as {getattr(me, 'first_name', None) or 'bot'} (@{me.username or me.id})\n")
    print("=" * 70)
    print("TELEGRAM_SESSION_STRING:")
    print(client.session.save())
    print("=" * 70)
    print("\nAlso set TELEGRAM_API_ID and TELEGRAM_API_HASH to the same values")
    print("you entered above, on the server. Keep all three secret.")
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
