import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

DB_PATH = os.getenv("DB_PATH", "scambot.db")
_lock = threading.Lock()


@contextmanager
def get_db():
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _new_case_id(db_conn):
    """Generate a collision-free AEGIS-XXXXXXXX ID. Must be called inside get_db()."""
    while True:
        cid = "AEGIS-" + secrets.token_hex(4).upper()
        if not db_conn.execute(
            "SELECT 1 FROM reports WHERE case_id = ?", (cid,)
        ).fetchone():
            return cid


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id TEXT NOT NULL UNIQUE,
                discord_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                added_at TEXT NOT NULL,
                added_by TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id TEXT NOT NULL,
                reporter_name TEXT NOT NULL,
                scammer_id TEXT,
                scammer_name TEXT,
                guild_id TEXT,
                guild_name TEXT,
                reported_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                context TEXT,
                case_id TEXT
            );
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL REFERENCES reports(id),
                url TEXT NOT NULL,
                domain TEXT
            );
            CREATE TABLE IF NOT EXISTS abuse_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL REFERENCES links(id),
                action_type TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                sent_at TEXT,
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS discord_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_user_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT
            );
            CREATE TABLE IF NOT EXISTS dropbox_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL REFERENCES links(id),
                dropbox_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'found',
                reported_at TEXT,
                notes TEXT
            );
            CREATE TABLE IF NOT EXISTS triage_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL REFERENCES links(id),
                exe_url TEXT NOT NULL,
                sample_id TEXT,
                report_url TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                submitted_at TEXT NOT NULL,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS provider_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                report_id INTEGER REFERENCES reports(id),
                from_addr TEXT,
                subject TEXT,
                body TEXT,
                received_at TEXT NOT NULL,
                notified INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL REFERENCES reports(id),
                admin_id TEXT NOT NULL,
                admin_name TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS site_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        # Migrations for columns added after initial schema
        existing_cols = {row[1] for row in db.execute("PRAGMA table_info(reports)")}
        if "case_id" not in existing_cols:
            db.execute("ALTER TABLE reports ADD COLUMN case_id TEXT")
        if "reporter_message" not in existing_cols:
            db.execute("ALTER TABLE reports ADD COLUMN reporter_message TEXT")


def create_report(reporter_id, reporter_name, scammer_id, scammer_name,
                  guild_id, guild_name, context, urls):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        case_id = _new_case_id(db)
        cur = db.execute(
            """INSERT INTO reports
               (reporter_id, reporter_name, scammer_id, scammer_name,
                guild_id, guild_name, reported_at, context, case_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (reporter_id, reporter_name, scammer_id, scammer_name,
             guild_id, guild_name, now, context, case_id)
        )
        report_id = cur.lastrowid
        for url in urls:
            domain = urlparse(url).hostname or ""
            db.execute(
                "INSERT INTO links (report_id, url, domain) VALUES (?, ?, ?)",
                (report_id, url, domain)
            )
    return report_id, case_id


def _hydrate_report(db, row):
    """Attach links, abuse_actions, and provider_responses to a report row dict."""
    report = dict(row)
    links = db.execute(
        "SELECT * FROM links WHERE report_id = ?", (report["id"],)
    ).fetchall()
    report["links"] = []
    for link in links:
        link = dict(link)
        actions = db.execute(
            "SELECT * FROM abuse_actions WHERE link_id = ? ORDER BY sent_at DESC",
            (link["id"],)
        ).fetchall()
        link["actions"] = [dict(a) for a in actions]
        triage = db.execute(
            "SELECT * FROM triage_results WHERE link_id = ? ORDER BY submitted_at",
            (link["id"],),
        ).fetchall()
        link["triage_results"] = [dict(t) for t in triage]
        dropbox = db.execute(
            "SELECT * FROM dropbox_findings WHERE link_id = ? ORDER BY reported_at",
            (link["id"],),
        ).fetchall()
        link["dropbox_findings"] = [dict(d) for d in dropbox]
        report["links"].append(link)
    responses = db.execute(
        "SELECT * FROM provider_responses WHERE report_id = ? ORDER BY received_at DESC",
        (report["id"],)
    ).fetchall()
    report["provider_responses"] = [dict(r) for r in responses]
    notes = db.execute(
        "SELECT * FROM case_notes WHERE report_id = ? ORDER BY created_at",
        (report["id"],)
    ).fetchall()
    report["case_notes"] = [dict(n) for n in notes]
    return report


def get_report(report_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        return _hydrate_report(db, row) if row else None


def get_report_by_case_id(case_id):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM reports WHERE case_id = ?", (case_id.upper(),)
        ).fetchone()
        return _hydrate_report(db, row) if row else None


def get_reports(status=None):
    with get_db() as db:
        if status and status != "all":
            rows = db.execute(
                "SELECT * FROM reports WHERE status = ? ORDER BY reported_at DESC",
                (status,)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM reports ORDER BY reported_at DESC"
            ).fetchall()
        reports = []
        for r in rows:
            report = dict(r)
            report["link_count"] = db.execute(
                "SELECT COUNT(*) FROM links WHERE report_id = ?", (report["id"],)
            ).fetchone()[0]
            reports.append(report)
        return reports


def get_reports_by_reporter(reporter_id, limit=5):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM reports WHERE reporter_id = ? ORDER BY reported_at DESC LIMIT ?",
            (reporter_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]


def get_links_for_report(report_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM links WHERE report_id = ?", (report_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def queue_notification(discord_user_id, message):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO discord_notifications (discord_user_id, message, created_at) VALUES (?, ?, ?)",
            (discord_user_id, message, now),
        )


def get_pending_notifications():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM discord_notifications WHERE sent_at IS NULL ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]


def mark_notification_sent(notification_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "UPDATE discord_notifications SET sent_at = ? WHERE id = ?",
            (now, notification_id),
        )


def store_dropbox_finding(link_id, dropbox_url, success, notes):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO dropbox_findings
               (link_id, dropbox_url, status, reported_at, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (link_id, dropbox_url, "reported" if success else "error", now, notes),
        )


def get_dropbox_findings_for_link(link_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM dropbox_findings WHERE link_id = ? ORDER BY reported_at",
            (link_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def store_triage_result(link_id, exe_url, sample_id, report_url, error=None):
    now = datetime.now(timezone.utc).isoformat()
    status = "error" if error else "submitted"
    with get_db() as db:
        db.execute(
            """INSERT INTO triage_results
               (link_id, exe_url, sample_id, report_url, status, submitted_at, error)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (link_id, exe_url, sample_id, report_url, status, now, error),
        )


def get_triage_results_for_link(link_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM triage_results WHERE link_id = ? ORDER BY submitted_at",
            (link_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_link(link_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM links WHERE id = ?", (link_id,)).fetchone()
        return dict(row) if row else None


def update_report_status(report_id, status):
    with get_db() as db:
        db.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))


def set_reporter_message(report_id, message):
    with get_db() as db:
        db.execute(
            "UPDATE reports SET reporter_message = ? WHERE id = ?",
            (message or None, report_id),
        )


def add_case_note(report_id, admin_id, admin_name, note):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO case_notes (report_id, admin_id, admin_name, note, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (report_id, admin_id, admin_name, note, now),
        )


def log_abuse_action(link_id, action_type, target, status, notes=""):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO abuse_actions
               (link_id, action_type, target, status, sent_at, notes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (link_id, action_type, target, status,
             now if status != "pending" else None, notes)
        )


def store_provider_response(case_id, from_addr, subject, body):
    """
    Store an inbound provider reply matched to a case ID.
    Returns the new row dict, or None if the case_id is unrecognised.
    """
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        report_row = db.execute(
            "SELECT id FROM reports WHERE case_id = ?", (case_id.upper(),)
        ).fetchone()
        if not report_row:
            return None
        report_id = report_row["id"]
        cur = db.execute(
            """INSERT INTO provider_responses
               (case_id, report_id, from_addr, subject, body, received_at, notified)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (case_id.upper(), report_id, from_addr, subject, body, now)
        )
        return {
            "id": cur.lastrowid,
            "case_id": case_id.upper(),
            "report_id": report_id,
            "from_addr": from_addr,
            "subject": subject,
            "body": body,
            "received_at": now,
        }


# ── Admin management ──────────────────────────────────────────────────────────

def get_admin(discord_id):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM admins WHERE discord_id = ?", (discord_id,)
        ).fetchone()
        return dict(row) if row else None


def list_admins():
    with get_db() as db:
        rows = db.execute("SELECT * FROM admins ORDER BY added_at").fetchall()
        return [dict(r) for r in rows]


def has_super_admin():
    with get_db() as db:
        return bool(
            db.execute("SELECT 1 FROM admins WHERE role = 'super_admin'").fetchone()
        )


def add_admin(discord_id, discord_name, role="admin", added_by=None):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO admins (discord_id, discord_name, role, added_at, added_by)
               VALUES (?, ?, ?, ?, ?)""",
            (discord_id, discord_name, role, now, added_by),
        )


def remove_admin(discord_id):
    with get_db() as db:
        db.execute(
            "DELETE FROM admins WHERE discord_id = ? AND role != 'super_admin'",
            (discord_id,),
        )


def get_setting(key, default=None):
    with get_db() as db:
        row = db.execute("SELECT value FROM site_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            """INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (key, value, now),
        )


def mark_response_notified(response_id):
    with get_db() as db:
        db.execute(
            "UPDATE provider_responses SET notified = 1 WHERE id = ?", (response_id,)
        )
