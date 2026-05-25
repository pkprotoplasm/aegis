from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import db
from api.deps import require_super_admin

router = APIRouter()


@router.get("/privacy")
def get_privacy():
    content = db.get_setting("privacy_policy", "")
    return {"content": content}


class PrivacyUpdate(BaseModel):
    content: str


@router.put("/privacy", dependencies=[Depends(require_super_admin)])
def set_privacy(body: PrivacyUpdate):
    db.set_setting("privacy_policy", body.content)
    return {"ok": True}
