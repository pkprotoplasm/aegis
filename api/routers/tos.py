from fastapi import APIRouter, Depends
from pydantic import BaseModel
import db
from api.deps import require_super_admin

router = APIRouter()


@router.get("/tos")
def get_tos():
    content = db.get_setting("terms_of_service", "")
    return {"content": content}


class ToSUpdate(BaseModel):
    content: str


@router.put("/tos", dependencies=[Depends(require_super_admin)])
def set_tos(body: ToSUpdate):
    db.set_setting("terms_of_service", body.content)
    return {"ok": True}
