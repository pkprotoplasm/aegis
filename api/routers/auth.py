"""Discord OAuth2 login / logout / session endpoints."""
import os
from datetime import datetime, timedelta, timezone

import requests as http
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from jose import jwt

import db
from api.deps import SESSION_COOKIE, get_current_user

router = APIRouter()

_DISCORD_API = "https://discord.com/api/v10"
_TOKEN_EXPIRE_HOURS = 24


def _make_session_token(discord_id: str, discord_name: str, role: str) -> str:
    secret = os.getenv("WEB_SECRET_KEY", "dev-secret-change-me")
    payload = {
        "sub":  discord_id,
        "name": discord_name,
        "role": role,
        "exp":  datetime.now(timezone.utc) + timedelta(hours=_TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _set_session_cookie(response: RedirectResponse, token: str):
    secure = os.getenv("COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=_TOKEN_EXPIRE_HOURS * 3600,
    )


@router.get("/auth/login")
def login():
    client_id   = os.getenv("DISCORD_CLIENT_ID", "")
    redirect_uri = os.getenv("DISCORD_REDIRECT_URI", "")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500,
                            detail="DISCORD_CLIENT_ID / DISCORD_REDIRECT_URI not configured")
    url = (
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        "&response_type=code"
        "&scope=identify"
    )
    return RedirectResponse(url)


@router.get("/auth/callback")
def callback(code: str):
    client_id     = os.getenv("DISCORD_CLIENT_ID", "")
    client_secret = os.getenv("DISCORD_CLIENT_SECRET", "")
    redirect_uri  = os.getenv("DISCORD_REDIRECT_URI", "")

    try:
        token_resp = http.post(
            f"{_DISCORD_API}/oauth2/token",
            data={
                "grant_type":   "authorization_code",
                "code":         code,
                "redirect_uri": redirect_uri,
                "client_id":    client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        user_resp = http.get(
            f"{_DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        user_resp.raise_for_status()
        discord_user = user_resp.json()
    except Exception:
        return RedirectResponse("/?error=oauth_failed")

    discord_id   = discord_user["id"]
    discord_name = discord_user.get("global_name") or discord_user.get("username", "Unknown")

    admin = db.get_admin(discord_id)
    if not admin:
        return RedirectResponse("/?error=unauthorized")

    token = _make_session_token(discord_id, discord_name, admin["role"])
    resp = RedirectResponse("/", status_code=302)
    _set_session_cookie(resp, token)
    return resp


@router.get("/auth/logout")
def logout():
    resp = RedirectResponse("/")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/auth/me")
def me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
