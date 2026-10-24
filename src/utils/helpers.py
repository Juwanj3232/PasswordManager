"""
Utility helpers for string formatting, domain parsing, and date display.
"""

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    """Extracts a clean domain name from a URL, or returns original string if not a URL."""
    if not url:
        return ""

    candidate = url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname or url
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname
    except Exception:
        return url


def format_iso_timestamp(iso_str: str) -> str:
    """Converts ISO 8601 string to a human-readable local date format."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%b %d, %Y %H:%M")
    except Exception:
        return iso_str[:10] if len(iso_str) >= 10 else iso_str
