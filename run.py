#!/usr/bin/env python3
"""Start the Discord bot, Flask dashboard, and IMAP monitor in one process."""
import os
import threading
from dotenv import load_dotenv

load_dotenv()

import db
db.init_db()

from web import create_app
import bot as discord_bot
from imap_monitor import IMAPMonitor


def run_web():
    app = create_app()
    port = int(os.getenv("WEB_PORT", 5000))
    print(f"Dashboard running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, use_reloader=False)


if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN is not set in .env")

    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()

    client = discord_bot.create_bot()

    # Start IMAP monitor once the Discord client exists so it can DM reporters
    monitor = IMAPMonitor(discord_client=client)
    monitor.start()

    client.run(token)
