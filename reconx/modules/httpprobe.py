from __future__ import annotations

import re
from dataclasses import dataclass

from reconx.core.logger import get_logger

log = get_logger()

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_TITLE = 120


@dataclass
class HTTPInfo:
    url: str
    status: int | None = None
    title: str = ""
    server: str = ""
    content_type: str = ""
    length: int | None = None
    location: str = ""
    error: str | None = None


def _extract_title(text: str) -> str:
    match = TITLE_RE.search(text or "")
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:MAX_TITLE]


def probe(session, host: str, schemes=("https", "http"), path: str = "/") -> HTTPInfo:
    last_error = None
    for scheme in schemes:
        url = f"{scheme}://{host}{path}"
        try:
            resp = session.get(url)
        except Exception as exc:
            last_error = str(exc)
            log.debug("probe %s failed: %s", url, exc)
            continue
        return HTTPInfo(
            url=str(resp.url),
            status=resp.status_code,
            title=_extract_title(resp.text),
            server=resp.headers.get("server", ""),
            content_type=resp.headers.get("content-type", ""),
            length=len(resp.content),
            location=resp.headers.get("location", ""),
        )
    return HTTPInfo(url=f"{schemes[-1]}://{host}{path}", error=last_error)
