"""Flask web dashboard for reviewing reports and triggering abuse actions."""
import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from urllib.parse import urlparse
import db
from abuse import whois_lookup, github as gh_abuse, hosting, phishing, intel as intel_mod


def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("WEB_SECRET_KEY", "dev-secret-change-me")

    @app.context_processor
    def inject_globals():
        from abuse.dryrun import is_dry_run
        return {"dry_run": is_dry_run()}

    @app.route("/")
    def index():
        status = request.args.get("status", "all")
        reports = db.get_reports(status)
        return render_template("index.html", reports=reports, current_status=status)

    @app.route("/report/<int:report_id>")
    def report_detail(report_id):
        report = db.get_report(report_id)
        if not report:
            flash("Report not found.", "error")
            return redirect(url_for("index"))
        # Annotate each link with GitHub Pages detection results so the
        # template can badge them and adjust the action button layout.
        for link in report["links"]:
            is_ghp, gh_user = gh_abuse.detect_github_pages(link.get("domain", ""))
            link["is_github_pages"] = is_ghp
            link["github_pages_user"] = gh_user
        return render_template("report.html", report=report)

    @app.route("/report/<int:report_id>/status", methods=["POST"])
    def update_status(report_id):
        status = request.form.get("status")
        if status in ("pending", "reviewed", "actioned", "dismissed"):
            db.update_report_status(report_id, status)
            flash(f"Status updated to '{status}'.", "success")
        return redirect(url_for("report_detail", report_id=report_id))

    @app.route("/link/<int:link_id>/action", methods=["POST"])
    def take_action(link_id):
        action = request.form.get("action")
        link = db.get_link(link_id)
        if not link:
            return jsonify({"error": "Link not found"}), 404

        report = db.get_report(link["report_id"])
        context = report.get("context", "") if report else ""
        url = link["url"]
        report_id = link["report_id"]

        case_id = report.get("case_id", "") or ""

        try:
            if action == "whois":
                success, target, notes = whois_lookup.report_whois(url, context, case_id)
                db.log_abuse_action(link_id, "whois_email", target,
                                    "sent" if success else "failed", notes)
                flash(f"WHOIS: {notes}" if success else "WHOIS: action failed — see action log.", "success" if success else "error")

            elif action == "hosting":
                success, target, notes, form_url = hosting.report_hosting(url, context, case_id)
                db.log_abuse_action(link_id, "hosting", target,
                                    "sent" if success else "failed", notes)
                flash(f"Hosting: {notes}" if success else "Hosting: action failed — see action log.", "success" if success else "error")

            elif action == "netcraft":
                success, notes = phishing.submit_to_netcraft(url)
                db.log_abuse_action(link_id, "netcraft", "report.netcraft.com",
                                    "sent" if success else "failed", notes)
                flash(f"Netcraft: {notes}" if success else "Netcraft: action failed — see action log.", "success" if success else "error")

            elif action == "github":
                if gh_abuse.is_github_url(url):
                    report_url, target = gh_abuse.get_github_report_url(url)
                    db.log_abuse_action(link_id, "github", target, "pending",
                                        f"Opened: {report_url}")
                    return redirect(report_url)
                else:
                    flash("Not a GitHub URL.", "error")

            elif action == "safebrowsing":
                report_url = phishing.get_google_safebrowsing_url(url)
                db.log_abuse_action(link_id, "safebrowsing", "safebrowsing.google.com",
                                    "pending", f"Opened: {report_url}")
                return redirect(report_url)

            else:
                flash("Unknown action.", "error")
        except Exception:
            flash("Action failed. Please try again.", "error")

        return redirect(url_for("report_detail", report_id=report_id))

    @app.route("/link/<int:link_id>/intel/whois")
    def link_intel_whois(link_id):
        link = db.get_link(link_id)
        if not link:
            return jsonify({"error": "Link not found"}), 404
        domain = link.get("domain") or urlparse(link["url"]).hostname or ""
        try:
            return jsonify(intel_mod.get_whois(domain))
        except Exception:
            return jsonify({"error": "WHOIS lookup failed"}), 502

    @app.route("/link/<int:link_id>/intel/host")
    def link_intel_host(link_id):
        link = db.get_link(link_id)
        if not link:
            return jsonify({"error": "Link not found"}), 404
        domain = link.get("domain") or urlparse(link["url"]).hostname or ""
        try:
            return jsonify(intel_mod.get_host_info(domain))
        except Exception:
            return jsonify({"error": "Host lookup failed"}), 502

    @app.route("/link/<int:link_id>/intel/reputation")
    def link_intel_reputation(link_id):
        link = db.get_link(link_id)
        if not link:
            return jsonify({"error": "Link not found"}), 404
        try:
            result = intel_mod.check_reputation(link["url"])
        except Exception:
            return jsonify({"error": "Reputation check failed"}), 502
        # Strip exception messages from error-status checks before sending to client
        result["checks"] = [
            {k: v for k, v in c.items() if not (k == "detail" and c.get("status") == "error")}
            for c in result.get("checks", [])
        ]
        return jsonify(result)

    return app
