"""FastAPI application — REST backend for the Aegis dashboard."""
from dotenv import load_dotenv

load_dotenv()

import db
db.init_db()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import reports, links, auth, admins

app = FastAPI(title="Aegis API", docs_url="/api/docs", openapi_url="/api/openapi.json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public endpoints (no auth required)
app.include_router(auth.router,    prefix="/api")

# Protected endpoints
app.include_router(reports.router, prefix="/api")
app.include_router(links.router,   prefix="/api")
app.include_router(admins.router,  prefix="/api")


@app.get("/api/config")
def config():
    from abuse.dryrun import is_dry_run
    return {"dry_run": is_dry_run()}
