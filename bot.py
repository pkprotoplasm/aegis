"""Discord bot — /report to submit scam links, /status to check case progress."""
import asyncio
import os
import re
import discord
from discord import app_commands
from discord.ext import tasks
import db
from abuse import triage as triage_mod, dropbox as dropbox_mod
from abuse import intel as intel_mod

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

_STATUS_COLORS = {
    "pending":   discord.Color.yellow(),
    "reviewed":  discord.Color.blue(),
    "actioned":  discord.Color.green(),
    "dismissed": discord.Color.dark_gray(),
}
_STATUS_EMOJI = {
    "pending": "🟡", "reviewed": "🔵", "actioned": "🟢", "dismissed": "⚫",
}


def extract_urls(text):
    return list(dict.fromkeys(URL_RE.findall(text)))  # deduplicated, order preserved


def _build_status_embed(report):
    embed = discord.Embed(
        title=f"Case {report['case_id'] or '(no ID)'}",
        color=_STATUS_COLORS.get(report["status"], discord.Color.greyple()),
    )
    embed.add_field(name="Status",          value=report["status"].capitalize(), inline=True)
    embed.add_field(name="Reported",        value=report["reported_at"][:10],    inline=True)
    embed.add_field(name="Links submitted", value=str(len(report["links"])),      inline=True)

    if report.get("context"):
        embed.add_field(name="Your description",
                        value=report["context"][:200], inline=False)

    # Actions taken across all links
    action_lines = []
    for link in report["links"]:
        for action in link["actions"]:
            icon = "✅" if action["status"] == "sent" \
                else "❌" if action["status"] == "failed" else "⏳"
            action_lines.append(
                f"{icon} **{action['action_type']}** → {action['target'] or '—'}"
            )
    embed.add_field(
        name="Actions taken",
        value="\n".join(action_lines[:10]) if action_lines else "None yet",
        inline=False,
    )

    # Provider responses
    responses = report.get("provider_responses", [])
    if responses:
        lines = [
            f"📧 **{r['from_addr']}** — *{r['subject'][:60]}*"
            for r in responses[:5]
        ]
        embed.add_field(
            name=f"Provider responses ({len(responses)})",
            value="\n".join(lines),
            inline=False,
        )
    else:
        embed.add_field(
            name="Provider responses",
            value="None yet — providers typically reply within 1–3 business days.",
            inline=False,
        )

    if report.get("reporter_message"):
        embed.add_field(
            name="Message from our team",
            value=report["reporter_message"],
            inline=False,
        )

    embed.set_footer(text="Responses are polled from the abuse inbox periodically.")
    return embed


async def _scan_and_triage(report_id):
    """Scan each submitted URL for EXE links and submit them to Triage."""
    api_key = os.getenv("TRIAGE_API_KEY", "")
    if not api_key:
        return

    loop = asyncio.get_event_loop()
    links = db.get_links_for_report(report_id)

    for link in links:
        exe_urls = await loop.run_in_executor(
            None, triage_mod.scan_for_exe_links, link["url"]
        )
        for exe_url in exe_urls[:5]:  # cap at 5 EXEs per link
            try:
                sample_id, report_url = await loop.run_in_executor(
                    None, triage_mod.submit_to_triage, exe_url, api_key
                )
                db.store_triage_result(link["id"], exe_url, sample_id, report_url)
                print(f"Triage: submitted {exe_url} → {report_url}")
            except Exception as e:
                db.store_triage_result(link["id"], exe_url, None, None, error=str(e))
                print(f"Triage: submission failed for {exe_url} — {e}")


async def _scan_dropbox(report_id, case_id, context):
    """Scan each submitted URL for Dropbox links and auto-report them."""
    loop = asyncio.get_event_loop()
    links = db.get_links_for_report(report_id)

    for link in links:
        dropbox_urls = await loop.run_in_executor(
            None, dropbox_mod.scan_for_dropbox_links, link["url"]
        )
        for dropbox_url in dropbox_urls[:10]:
            success, notes = await loop.run_in_executor(
                None, dropbox_mod.send_dropbox_abuse_report,
                dropbox_url, link["url"], context or "", case_id
            )
            db.store_dropbox_finding(link["id"], dropbox_url, success, notes)
            print(f"Dropbox: {'reported' if success else 'failed'} {dropbox_url} — {notes}")


async def _scan_and_warn(client, reporter_id, report_id, case_id, urls):
    """
    Run all automated on-submit threat checks in sequence:
      1. File-sharing link scan (page body)
      2. Google Safe Browsing lookup (if key configured)
      3. urlscan.io submission + verdict poll (if key configured; UUID stored for admin panel)

    If any check finds a threat, a single consolidated case note is added, the reporter
    message is set (unless an admin has already written one), and the reporter is DMed.
    """
    loop = asyncio.get_event_loop()
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    # threat_rows: list of (url, source_label, detail) for the case note
    threat_rows: list[tuple[str, str, str]] = []
    sources: set[str] = set()

    # ── 1. File-sharing link scan ─────────────────────────────────────────
    for url in urls:
        hits = await loop.run_in_executor(None, dropbox_mod.scan_for_fileshare_links, url)
        if hits:
            sites = ", ".join(sorted({h["site"] for h in hits}))
            threat_rows.append((url, "File-sharing links", sites))
            sources.add("file-sharing services")
            print(f"bot: fileshare links in {url} ({sites})")

    # ── 2. Google Safe Browsing ───────────────────────────────────────────
    if gsb_key:
        for url in urls:
            result = await loop.run_in_executor(
                None, intel_mod._check_gsb, url, gsb_key
            )
            if result.get("status") == "listed":
                detail = ", ".join(result.get("threat_types") or [])
                threat_rows.append((url, "Google Safe Browsing", detail))
                sources.add("Google Safe Browsing")
                print(f"bot: GSB flagged {url} ({detail})")

    # ── 3. urlscan.io — submit, store UUID, poll for verdict ─────────────
    links = db.get_links_for_report(report_id)
    for link in links:
        uuid = await loop.run_in_executor(None, intel_mod.submit_urlscan, link["url"])
        if not uuid:
            continue
        db.store_urlscan_uuid(link["id"], uuid)
        print(f"urlscan.io: submitted {link['url']} → {uuid}")
        result = await loop.run_in_executor(None, intel_mod.fetch_urlscan_result, uuid)
        if result and (result.get("verdict") or {}).get("malicious"):
            verdict = result["verdict"]
            score = verdict.get("score", "?")
            cats  = verdict.get("categories") or []
            detail = f"malicious, score {score}" + (f" ({', '.join(cats)})" if cats else "")
            threat_rows.append((link["url"], "urlscan.io", detail))
            sources.add("urlscan.io")
            print(f"bot: urlscan.io verdict malicious for {link['url']} (score {score})")

    if not threat_rows:
        return

    # ── Case note (admin-facing) ──────────────────────────────────────────
    note_lines = ["Automated threat scan findings at submission time:"]
    for url, source, detail in threat_rows:
        note_lines.append(f"  • [{source}] {url}\n    {detail}")
    db.add_case_note(report_id, "system", "Aegis", "\n".join(note_lines))

    # ── Reporter message (shown via /status) ──────────────────────────────
    report = db.get_report(report_id)
    if not (report or {}).get("reporter_message"):
        source_str = " and ".join(sorted(sources))
        db.set_reporter_message(
            report_id,
            f"One or more of the URLs you reported have been flagged by automated "
            f"threat checks ({source_str}). Do not click any links or open any files "
            f"or downloads from the URLs you reported until you receive confirmation "
            f"from Aegis following our review.",
        )

    # ── DM the reporter ───────────────────────────────────────────────────
    source_str = " and ".join(sorted(sources))
    try:
        user = await client.fetch_user(int(reporter_id))
        await user.send(
            f"**Safety notice — Case `{case_id}`**\n\n"
            f"One or more of the URLs you reported have been flagged by automated "
            f"threat checks ({source_str}). These may be dangerous.\n\n"
            f"**Do not click any links or open any files or downloads** from the URLs "
            f"you reported until you receive a follow-up from Aegis following our review.\n\n"
            f"*Aegis — Automated Effective Guard against Information Stealers*"
        )
    except Exception as e:
        print(f"bot: could not DM reporter {reporter_id} threat warning — {e}")


async def _notify_admins(client, report_id, case_id, reporter_name, urls, context):
    """DM every admin a new-report notification with a link to the dashboard."""
    base_url = os.getenv("WEB_BASE_URL", "http://localhost:5000").rstrip("/")
    portal_link = f"{base_url}/report/{report_id}"

    url_preview = "\n".join(f"• {u}" for u in urls[:5])
    if len(urls) > 5:
        url_preview += f"\n… and {len(urls) - 5} more"

    embed = discord.Embed(
        title=f"New report — `{case_id}`",
        color=discord.Color.yellow(),
        url=portal_link,
    )
    embed.add_field(name="Reporter", value=reporter_name, inline=True)
    embed.add_field(name="Links",    value=str(len(urls)), inline=True)
    if context:
        embed.add_field(name="Context", value=context[:200], inline=False)
    embed.add_field(name="Submitted URLs", value=url_preview, inline=False)
    embed.add_field(name="Review", value=f"[Open in dashboard]({portal_link})", inline=False)
    embed.set_footer(text="Aegis — Automated Effective Guard against Information Stealers")

    for admin in db.list_admins():
        try:
            user = await client.fetch_user(int(admin["discord_id"]))
            await user.send(embed=embed)
        except Exception as e:
            print(f"bot: could not notify admin {admin['discord_name']} — {e}")


class ReportModal(discord.ui.Modal, title="Report a Scammer"):
    scammer = discord.ui.TextInput(
        label="Scammer's Discord username or ID",
        placeholder="e.g. badactor#1234 or 123456789012345678",
        required=False,
        max_length=100,
    )
    links = discord.ui.TextInput(
        label="Suspicious links (one per line or paste text)",
        style=discord.TextStyle.paragraph,
        placeholder="https://totally-legit-site.xyz/free-nitro",
        required=True,
        max_length=2000,
    )
    context = discord.ui.TextInput(
        label="What happened? (optional)",
        style=discord.TextStyle.paragraph,
        placeholder="They offered free Discord Nitro and asked me to log in…",
        required=False,
        max_length=1000,
    )

    def __init__(self, client):
        super().__init__()
        self._client = client

    async def on_submit(self, interaction: discord.Interaction):
        urls = extract_urls(self.links.value)
        if not urls:
            await interaction.response.send_message(
                "No valid URLs (starting with http:// or https://) found in your submission. "
                "Please try again with the actual links.",
                ephemeral=True,
            )
            return

        guild = interaction.guild
        report_id, case_id = db.create_report(
            reporter_id=str(interaction.user.id),
            reporter_name=str(interaction.user),
            scammer_id=self.scammer.value.strip() or None,
            scammer_name=self.scammer.value.strip() or None,
            guild_id=str(guild.id) if guild else None,
            guild_name=str(guild.name) if guild else None,
            context=self.context.value.strip() or None,
            urls=urls,
        )

        # Acknowledge the reporter immediately, then notify admins in the background
        url_list = "\n".join(f"• {u}" for u in urls)
        await interaction.response.send_message(
            f"**Report received — thank you.**\n\n"
            f"Your case ID is: **`{case_id}`**\n"
            f"Use `/status case_id:{case_id}` at any time to check progress.\n\n"
            f"Submitted {len(urls)} link(s) for review:\n{url_list}\n\n"
            f"*Aegis — Automated Effective Guard against Information Stealers*",
            ephemeral=True,
        )

        interaction.client.loop.create_task(
            _notify_admins(self._client, report_id, case_id,
                           str(interaction.user), urls,
                           self.context.value.strip() or None)
        )
        interaction.client.loop.create_task(_scan_and_triage(report_id))
        interaction.client.loop.create_task(
            _scan_dropbox(report_id, case_id, self.context.value.strip() or None)
        )
        interaction.client.loop.create_task(
            _scan_and_warn(
                self._client, str(interaction.user.id), report_id, case_id, urls
            )
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        await interaction.response.send_message(
            "Something went wrong processing your report. Please try again.",
            ephemeral=True,
        )
        raise error


def create_bot():
    intents = discord.Intents.default()
    client = discord.Client(intents=intents)
    tree = app_commands.CommandTree(client)

    @tasks.loop(seconds=30)
    async def drain_notifications():
        for notif in db.get_pending_notifications():
            try:
                user = await client.fetch_user(int(notif["discord_user_id"]))
                await user.send(notif["message"])
                db.mark_notification_sent(notif["id"])
            except Exception as e:
                print(f"bot: notification failed for user {notif['discord_user_id']} — {e}")

    @client.event
    async def on_ready():
        await tree.sync()
        drain_notifications.start()
        print(f"Logged in as {client.user} — slash commands synced")

    @tree.command(name="report",
                  description="Report a suspicious link or scammer to Aegis for investigation")
    async def report_cmd(interaction: discord.Interaction):
        await interaction.response.send_modal(ReportModal(client))

    @tree.command(name="status",
                  description="Check the status of your scam report")
    @app_commands.describe(
        case_id="Your case ID (e.g. AEGIS-A3F2B8C1). Leave blank to see your recent reports."
    )
    async def status_cmd(interaction: discord.Interaction, case_id: str = None):
        reporter_id = str(interaction.user.id)

        if case_id:
            case_id = case_id.strip().upper()
            report = db.get_report_by_case_id(case_id)
            if not report or report["reporter_id"] != reporter_id:
                await interaction.response.send_message(
                    f"No report found for case `{case_id}`, "
                    "or it doesn't belong to your account.",
                    ephemeral=True,
                )
                return
            await interaction.response.send_message(
                embed=_build_status_embed(report), ephemeral=True
            )
            return

        # No case_id given — list the user's recent reports
        reports = db.get_reports_by_reporter(reporter_id, limit=5)
        if not reports:
            await interaction.response.send_message(
                "You have no reports on file. Use `/report` to submit one.",
                ephemeral=True,
            )
            return

        if len(reports) == 1:
            report = db.get_report(reports[0]["id"])
            await interaction.response.send_message(
                embed=_build_status_embed(report), ephemeral=True
            )
            return

        lines = ["**Your recent cases** — use `/status case_id:<ID>` for full details:\n"]
        for r in reports:
            emoji = _STATUS_EMOJI.get(r["status"], "⚪")
            cid = r.get("case_id") or "(no ID)"
            lines.append(f"{emoji} `{cid}` — {r['status']} — {r['reported_at'][:10]}")
        await interaction.response.send_message("\n".join(lines), ephemeral=True)

    def _is_super_admin(interaction: discord.Interaction) -> bool:
        admin = db.get_admin(str(interaction.user.id))
        return bool(admin and admin["role"] == "super_admin")

    @tree.command(name="add-admin",
                  description="Grant a user access to the Aegis dashboard (super admin only)")
    @app_commands.describe(user="The Discord user to add as a dashboard admin")
    async def add_admin_cmd(interaction: discord.Interaction, user: discord.Member):
        if not _is_super_admin(interaction):
            await interaction.response.send_message(
                "Only the super admin can add dashboard admins.", ephemeral=True
            )
            return

        if db.get_admin(str(user.id)):
            await interaction.response.send_message(
                f"{user.mention} is already a dashboard admin.", ephemeral=True
            )
            return

        db.add_admin(str(user.id), user.display_name,
                     role="admin", added_by=str(interaction.user.id))

        await interaction.response.send_message(
            f"✅ {user.mention} has been added as a dashboard admin.", ephemeral=True
        )
        try:
            base_url = os.getenv("WEB_BASE_URL", "http://localhost:5000").rstrip("/")
            await user.send(
                f"You've been granted access to the **Aegis Dashboard** by "
                f"{interaction.user.mention}.\n{base_url}"
            )
        except Exception:
            pass  # DMs may be disabled

    @tree.command(name="remove-admin",
                  description="Revoke a user's access to the Aegis dashboard (super admin only)")
    @app_commands.describe(user="The dashboard admin to remove")
    async def remove_admin_cmd(interaction: discord.Interaction, user: discord.Member):
        if not _is_super_admin(interaction):
            await interaction.response.send_message(
                "Only the super admin can remove dashboard admins.", ephemeral=True
            )
            return

        target = db.get_admin(str(user.id))
        if not target:
            await interaction.response.send_message(
                f"{user.mention} is not a dashboard admin.", ephemeral=True
            )
            return

        if target["role"] == "super_admin":
            await interaction.response.send_message(
                "The super admin cannot be removed.", ephemeral=True
            )
            return

        db.remove_admin(str(user.id))
        await interaction.response.send_message(
            f"✅ {user.mention}'s dashboard access has been revoked.", ephemeral=True
        )

    return client
