"""Dry-run guard — set DRY_RUN=1 to log actions without sending anything."""
import os


def is_dry_run() -> bool:
    return os.getenv("DRY_RUN", "").strip() in ("1", "true", "yes")
