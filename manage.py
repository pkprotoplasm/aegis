#!/usr/bin/env python3
"""Management CLI for Aegis. Run with: python manage.py <command> [args]"""
import os
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


def cmd_retriage(args):
    """retriage <case_id>  —  Re-scan all links in a report and submit any new sample files to Triage."""
    if len(args) < 1:
        print("Usage: python manage.py retriage <case_id>")
        sys.exit(1)

    api_key = os.getenv("TRIAGE_API_KEY", "")
    if not api_key:
        print("TRIAGE_API_KEY is not set in .env")
        sys.exit(1)

    db.init_db()

    from abuse import triage as triage_mod

    report = db.get_report_by_case_id(args[0])
    if not report:
        print(f"No report found for case ID: {args[0]!r}")
        sys.exit(1)

    print(f"Report {report['case_id']} — {len(report['links'])} link(s)")

    for link in report["links"]:
        print(f"\n  Scanning: {link['url']}")
        try:
            sample_urls = triage_mod.scan_for_sample_links(link["url"])
        except Exception as e:
            print(f"    Scan error: {e}")
            continue

        if not sample_urls:
            print("    No sample files found.")
            continue

        already_submitted = {t["exe_url"] for t in link["triage_results"]}

        for sample_url in sample_urls[:5]:
            if sample_url in already_submitted:
                print(f"    Already submitted: {sample_url}")
                continue
            try:
                sample_id, report_url = triage_mod.submit_to_triage(sample_url, api_key)
                db.store_triage_result(link["id"], sample_url, sample_id, report_url)
                print(f"    Submitted: {sample_url} → {report_url}")
            except Exception as e:
                db.store_triage_result(link["id"], sample_url, None, None, error=str(e))
                print(f"    Submission failed for {sample_url}: {e}")


COMMANDS = {
    "add-superadmin":     cmd_add_superadmin,
    "replace-superadmin": cmd_replace_superadmin,
    "list-admins":        cmd_list_admins,
    "retriage":           cmd_retriage,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python manage.py <command>")
        print("Commands:")
        for name, fn in COMMANDS.items():
            print(f"  {name}  —  {fn.__doc__}")
        sys.exit(1)

    COMMANDS[sys.argv[1]](sys.argv[2:])
