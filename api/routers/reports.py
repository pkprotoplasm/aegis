from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import db
from abuse import github as gh_abuse
from api.deps import require_user

router = APIRouter(dependencies=[Depends(require_user)])


@router.get("/reports")
def list_reports(status: str = "all"):
    return db.get_reports(status)


@router.get("/reports/{report_id}")
def get_report(report_id: int):
    report = db.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    for link in report["links"]:
        is_ghp, gh_user = gh_abuse.detect_github_pages(link.get("domain", ""))
        link["is_github_pages"] = is_ghp
        link["github_pages_user"] = gh_user
    return report


class StatusUpdate(BaseModel):
    status: str


_STATUS_EMOJI = {
    "pending":   "🟡",
    "reviewed":  "🔵",
    "actioned":  "🟢",
    "dismissed": "⚫",
}

@router.put("/reports/{report_id}/status")
def update_status(report_id: int, body: StatusUpdate):
    if body.status not in ("pending", "reviewed", "actioned", "dismissed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    report = db.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report["status"] == body.status:
        return {"ok": True}
    db.update_report_status(report_id, body.status)

    emoji = _STATUS_EMOJI.get(body.status, "⚪")
    case_id = report.get("case_id") or f"#{report_id}"
    message = (
        f"{emoji} **Update on your case `{case_id}`**\n\n"
        f"Status changed to: **{body.status.capitalize()}**\n\n"
        f"Use `/status case_id:{case_id}` for full details."
    )
    db.queue_notification(report["reporter_id"], message)

    return {"ok": True}
