"""Admin management endpoints — super admin only."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import db
from api.deps import require_super_admin

router = APIRouter(dependencies=[Depends(require_super_admin)])


class AddAdminRequest(BaseModel):
    discord_id:   str
    discord_name: str


@router.get("/admins")
def list_admins():
    return db.list_admins()


@router.post("/admins")
def add_admin(body: AddAdminRequest):
    if db.get_admin(body.discord_id):
        raise HTTPException(status_code=409, detail="That Discord account is already an admin")
    db.add_admin(body.discord_id, body.discord_name, role="admin")
    return {"ok": True}


@router.delete("/admins/{discord_id}")
def remove_admin(discord_id: str):
    target = db.get_admin(discord_id)
    if not target:
        raise HTTPException(status_code=404, detail="Admin not found")
    if target["role"] == "super_admin":
        raise HTTPException(status_code=403, detail="The super admin cannot be removed")
    db.remove_admin(discord_id)
    return {"ok": True}
