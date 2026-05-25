"""FastAPI dependencies for authentication and authorization."""
import os
from fastapi import Request, HTTPException
from jose import jwt, JWTError

SESSION_COOKIE = "aegis_session"


def get_current_user(request: Request):
    """Return the session user dict, or None if not authenticated."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        secret = os.getenv("WEB_SECRET_KEY", "dev-secret-change-me")
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return {
            "discord_id":   payload["sub"],
            "discord_name": payload["name"],
            "role":         payload["role"],
        }
    except JWTError:
        return None


def require_user(request: Request):
    """Dependency: require any authenticated user."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_super_admin(request: Request):
    """Dependency: require the super admin role."""
    user = require_user(request)
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin access required")
    return user
