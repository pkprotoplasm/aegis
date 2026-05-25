#!/usr/bin/env python3
"""Management CLI for Aegis. Run with: python manage.py <command> [args]"""
import sys
from dotenv import load_dotenv

load_dotenv()

import db


def cmd_add_superadmin(args):
    """add-superadmin <discord_id> <username>  —  Bootstrap the first super admin."""
    if len(args) < 2:
        print("Usage: python manage.py add-superadmin <discord_id> <username>")
        sys.exit(1)

    discord_id, username = args[0], args[1]

    db.init_db()

    if db.has_super_admin():
        print("A super admin already exists. Use the dashboard to manage admins.")
        sys.exit(1)

    db.add_admin(discord_id, username, role="super_admin", added_by="cli")
    print(f"Super admin added: {username} (Discord ID: {discord_id})")
    print("You can now log in to the dashboard with this Discord account.")


def cmd_replace_superadmin(args):
    """replace-superadmin <discord_id> <username>  —  Replace the existing super admin."""
    if len(args) < 2:
        print("Usage: python manage.py replace-superadmin <discord_id> <username>")
        sys.exit(1)

    discord_id, username = args[0], args[1]

    db.init_db()

    with db.get_db() as conn:
        conn.execute("DELETE FROM admins WHERE role = 'super_admin'")
        from datetime import datetime, timezone
        conn.execute(
            "INSERT INTO admins (discord_id, discord_name, role, added_at, added_by) VALUES (?, ?, 'super_admin', ?, 'cli')",
            (discord_id, username, datetime.now(timezone.utc).isoformat()),
        )

    print(f"Super admin replaced: {username} (Discord ID: {discord_id})")


def cmd_list_admins(args):
    """list-admins  —  Show all current admins."""
    db.init_db()
    admins = db.list_admins()
    if not admins:
        print("No admins configured.")
        return
    for a in admins:
        role_label = "[SUPER ADMIN]" if a["role"] == "super_admin" else "[admin]"
        print(f"  {role_label} {a['discord_name']} ({a['discord_id']})  added {a['added_at'][:10]}")


COMMANDS = {
    "add-superadmin":     cmd_add_superadmin,
    "replace-superadmin": cmd_replace_superadmin,
    "list-admins":        cmd_list_admins,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python manage.py <command>")
        print("Commands:")
        for name, fn in COMMANDS.items():
            print(f"  {name}  —  {fn.__doc__}")
        sys.exit(1)

    COMMANDS[sys.argv[1]](sys.argv[2:])
