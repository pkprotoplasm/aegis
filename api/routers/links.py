from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from urllib.parse import urlparse
import db
from abuse import whois_lookup, github as gh_abuse, hosting, phishing
from abuse import intel as intel_mod
from api.deps import require_user

router = APIRouter(dependencies=[Depends(require_user)])


class ActionRequest(BaseModel):
    action: str
    extra_context: str = ""


@router.post("/links/{link_id}/preview")
def preview_action(link_id: int, body: ActionRequest):
    """
    Return the email that would be sent for an action without sending it.
    Returns {to, subject, body}. Only supported for email actions (whois, hosting).
    """
    action = body.action
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    report = db.get_report(link["report_id"])
    context = report.get("context", "") if report else ""
    url = link["url"]
    case_id = (report.get("case_id") or "") if report else ""
    triage_results = db.get_triage_results_for_link(link_id)

    try:
        if action == "whois":
            return whois_lookup.preview_whois(url, context, case_id, triage_results,
                                              body.extra_context)
        elif action == "hosting":
            return hosting.preview_hosting(url, context, case_id, triage_results,
                                           body.extra_context)
        raise HTTPException(status_code=400, detail=f"Preview not supported for action '{action}'")
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        raise HTTPException(status_code=502, detail="Preview failed")


@router.post("/links/{link_id}/action")
def take_action(link_id: int, body: ActionRequest):
    action = body.action
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    report = db.get_report(link["report_id"])
    context = report.get("context", "") if report else ""
    url = link["url"]
    case_id = (report.get("case_id") or "") if report else ""
    triage_results = db.get_triage_results_for_link(link_id)

    try:
        if action == "whois":
            success, target, notes = whois_lookup.report_whois(url, context, case_id,
                                                                triage_results, body.extra_context)
            db.log_abuse_action(link_id, "whois_email", target,
                                "sent" if success else "failed", notes)
            return {"success": success, "notes": notes}

        elif action == "hosting":
            success, target, notes, form_url = hosting.report_hosting(url, context, case_id,
                                                                       triage_results, body.extra_context)
            db.log_abuse_action(link_id, "hosting", target,
                                "sent" if success else "failed", notes)
            return {"success": success, "notes": notes}

        elif action == "netcraft":
            success, notes = phishing.submit_to_netcraft(url)
            db.log_abuse_action(link_id, "netcraft", "report.netcraft.com",
                                "sent" if success else "failed", notes)
            return {"success": success, "notes": notes}

        elif action == "github":
            if gh_abuse.is_github_url(url):
                report_url, target = gh_abuse.get_github_report_url(url)
                db.log_abuse_action(link_id, "github", target, "pending",
                                    f"Opened: {report_url}")
                return {"success": True, "redirect_url": report_url,
                        "notes": "Opened GitHub report form"}
            raise HTTPException(status_code=400, detail="Not a GitHub URL")

        elif action == "safebrowsing":
            report_url = phishing.get_google_safebrowsing_url(url)
            db.log_abuse_action(link_id, "safebrowsing", "safebrowsing.google.com",
                                "pending", f"Opened: {report_url}")
            return {"success": True, "redirect_url": report_url,
                    "notes": "Opened Google Safe Browsing report form"}

        raise HTTPException(status_code=400, detail="Unknown action")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=502, detail="Action failed")


@router.get("/links/{link_id}/intel/whois")
def intel_whois(link_id: int):
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    domain = link.get("domain") or urlparse(link["url"]).hostname or ""
    try:
        return intel_mod.get_whois(domain)
    except Exception:
        raise HTTPException(status_code=502, detail="WHOIS lookup failed")


@router.get("/links/{link_id}/intel/host")
def intel_host(link_id: int):
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    domain = link.get("domain") or urlparse(link["url"]).hostname or ""
    try:
        return intel_mod.get_host_info(domain)
    except Exception:
        raise HTTPException(status_code=502, detail="Host lookup failed")


@router.get("/links/{link_id}/intel/reputation")
def intel_reputation(link_id: int):
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    try:
        return intel_mod.check_reputation(link["url"])
    except Exception:
        raise HTTPException(status_code=502, detail="Reputation check failed")


@router.get("/links/{link_id}/intel/urlscan")
def intel_urlscan(link_id: int):
    link = db.get_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    try:
        return intel_mod.check_urlscan(link["url"], stored_uuid=link.get("urlscan_uuid"))
    except Exception:
        raise HTTPException(status_code=502, detail="urlscan.io lookup failed")
