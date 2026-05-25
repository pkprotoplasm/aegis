#!/usr/bin/env python3
"""Start the Discord bot and IMAP monitor (no web server — API runs separately)."""
import os
from dotenv import load_dotenv

load_dotenv()

import db
db.init_db()

import bot as discord_bot
from imap_monitor import IMAPMonitor

if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN is not set in .env")

    client = discord_bot.create_bot()

    monitor = IMAPMonitor(discord_client=client)
    monitor.start()

    client.run(token)
