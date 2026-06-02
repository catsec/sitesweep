"""sitesweep web — Hebrew front end over the sitesweep engine.

Endpoints:
  GET  /            Hebrew RTL single-page UI
  GET  /health      liveness probe (for container healthcheck)
  POST /api/scan    run a scan (URL crawl or HAR upload) -> Hebrew JSON report
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

import sitesweep as ss

app = FastAPI(title="sitesweep", docs_url=None, redoc_url=None, openapi_url=None)

TEMPLATES = Path(__file__).parent / "templates"
INDEX_HTML = (TEMPLATES / "index.html").read_text(encoding="utf-8")
LOGO_PATH = TEMPLATES / "catsec.png"

MAX_HAR_BYTES = int(os.environ.get("SITESWEEP_MAX_HAR_MB", "40")) * 1024 * 1024
MAX_PAGES_CAP = int(os.environ.get("SITESWEEP_MAX_PAGES", "50"))
ALLOW_RENDER = os.environ.get("SITESWEEP_ALLOW_RENDER", "1") == "1"


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return INDEX_HTML


@app.get("/catsec.png", include_in_schema=False)
async def logo() -> FileResponse:
    return FileResponse(LOGO_PATH, media_type="image/png")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(
    mode: str = Form("url"),
    url: str = Form(""),
    depth: int = Form(1),
    max_pages: int = Form(20),
    render: bool = Form(False),
    cloak: bool = Form(True),
    har: UploadFile | None = File(None),
):
    try:
        if mode == "har":
            if har is None:
                raise HTTPException(400, "לא הועלה קובץ HAR")
            raw = await har.read()
            if len(raw) > MAX_HAR_BYTES:
                raise HTTPException(413, "קובץ ה-HAR גדול מדי")
            try:
                parsed = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                raise HTTPException(400, "קובץ ה-HAR אינו תקין (JSON שגוי)")
            if "log" not in parsed or "entries" not in parsed.get("log", {}):
                raise HTTPException(400, "המבנה אינו נראה כקובץ HAR תקין")
            report = ss.scan_har_dict(parsed)
            report.start_url = har.filename or "(HAR capture)"
        else:
            u = (url or "").strip()
            if not u:
                raise HTTPException(400, "נא להזין כתובת אתר")
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            if not urlparse(u).netloc:
                raise HTTPException(400, "כתובת האתר אינה תקינה")
            depth = max(0, min(int(depth), 2))
            max_pages = max(1, min(int(max_pages), MAX_PAGES_CAP))
            use_render = bool(render) and ALLOW_RENDER
            report = await ss.scan_url(u, depth=depth, max_pages=max_pages,
                                       render=use_render, cloak=bool(cloak))

        return JSONResponse(ss.report_to_dict(report, "he"))

    except HTTPException:
        raise
    except SystemExit as e:  # headless Chrome unavailable
        raise HTTPException(500, f"מנוע הדפדפן אינו זמין: {e}")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"שגיאה במהלך הסריקה: {type(e).__name__}: {e}")
