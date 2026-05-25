"""
Background thread that polls an IMAP inbox for provider replies to abuse reports.

Any UNSEEN message whose Subject or body contains a AEGIS-XXXXXXXX case ID is:
  - stored in provider_responses
  - used to DM the original reporter via Discord (if the client is supplied)
  - marked as Seen in the mailbox

Messages that contain no recognisable case ID are left UNSEEN and untouched.
"""
import asyncio
import email as email_lib
import email.header
import imaplib
import os
import re
import threading

import db
from abuse.dryrun import is_dry_run

CASE_ID_RE = re.compile(r"\bAEGIS-[A-F0-9]{8}\b", re.IGNORECASE)


def _decode_header(value):
    parts = email.header.decode_header(value or "")
    out = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out)


def _extract_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(
                msg.get_content_charset() or "utf-8", errors="replace"
            )
    return ""


class IMAPMonitor:
    def __init__(self, discord_client=None):
        self.host = os.getenv("IMAP_HOST", "")
        self.port = int(os.getenv("IMAP_PORT", 993))
        self.user = os.getenv("IMAP_USER", "")
        self.password = os.getenv("IMAP_PASS", "")
        self.interval = int(os.getenv("IMAP_POLL_INTERVAL", 300))
        self.discord_client = discord_client
        self._stop = threading.Event()

    def start(self):
        if not (self.host and self.user and self.password):
            print("IMAP monitor: IMAP_HOST / IMAP_USER / IMAP_PASS not set — skipping")
            return
        print(
            f"IMAP monitor: polling {self.user}@{self.host} "
            f"every {self.interval}s for case-ID replies"
        )
        threading.Thread(target=self._run, daemon=True, name="imap-monitor").start()

    def _run(self):
        # Poll immediately on start, then wait between subsequent runs
        while True:
            try:
                self._poll()
            except Exception as e:
                print(f"IMAP monitor: poll error — {e}")
            if self._stop.wait(self.interval):
                break

    def _poll(self):
        with imaplib.IMAP4_SSL(self.host, self.port) as imap:
            imap.login(self.user, self.password)
            imap.select("INBOX")
            _, data = imap.search(None, "UNSEEN")
            msg_ids = data[0].split()
            if not msg_ids:
                return
            print(f"IMAP monitor: {len(msg_ids)} new message(s)")
            for msg_id in msg_ids:
                try:
                    self._process(imap, msg_id)
                except Exception as e:
                    print(f"IMAP monitor: error on message {msg_id} — {e}")

    def _process(self, imap, msg_id):
        _, msg_data = imap.fetch(msg_id, "(RFC822)")
        raw = msg_data[0][1]
        msg = email_lib.message_from_bytes(raw)

        subject = _decode_header(msg.get("Subject", ""))
        from_addr = _decode_header(msg.get("From", ""))
        body = _extract_text(msg)

        case_ids = {m.upper() for m in CASE_ID_RE.findall(subject + "\n" + body)}
        if not case_ids:
            return  # Not one of ours — leave UNSEEN

        for case_id in case_ids:
            response = db.store_provider_response(
                case_id=case_id,
                from_addr=from_addr,
                subject=subject,
                body=body[:4000],
            )
            if response:
                print(f"IMAP monitor: stored response for {case_id} from {from_addr!r}")
                self._schedule_dm(response)

        if is_dry_run():
            print(f"[DRY RUN] Would mark message {msg_id} as Seen")
        else:
            imap.store(msg_id, "+FLAGS", "\\Seen")

    def _schedule_dm(self, response):
        client = self.discord_client
        if not client or not client.loop or client.loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self._send_dm(response), client.loop)

    async def _send_dm(self, response):
        try:
            report = db.get_report_by_case_id(response["case_id"])
            if not report:
                return
            user = await self.discord_client.fetch_user(int(report["reporter_id"]))
            await user.send(
                f"**Update on your scam report — Case `{response['case_id']}`**\n\n"
                f"A response was received from **{response['from_addr']}**\n"
                f"Subject: *{response['subject']}*\n\n"
                f"Use `/status case_id:{response['case_id']}` to see full details."
            )
            db.mark_response_notified(response["id"])
        except Exception as e:
            print(f"IMAP monitor: failed to DM reporter — {e}")
