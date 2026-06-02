"""sitesweep web — Hebrew front end over the sitesweep engine.

Scans can take longer than the ~100s timeout of a proxy in front of the app
(e.g. Cloudflare, which returns an HTML 524 page on a slow origin). So scanning
is asynchronous: POST /api/scan starts a job and returns a job id immediately,
and the browser polls GET /api/scan/{id} for the result. Every request through
the proxy is then fast, regardless of how long the scan itself runs.

Endpoints:
  GET  /                 Hebrew RTL single-page UI
  GET  /health           liveness probe (for container healthcheck)
  POST /api/scan         start a scan (URL crawl or HAR upload) -> {"job_id": ...}
  GET  /api/scan/{id}    poll job status -> running | done (+report) | error
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
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
# Hard wall-clock cap on a single scan so an abandoned/stuck job can't pin a
# browser (or memory) forever. Generous by default; tune per deployment.
SCAN_TIMEOUT = int(os.environ.get("SITESWEEP_SCAN_TIMEOUT", "300"))

# In-memory job store. Safe because the app runs as a single uvicorn worker;
# results are ephemeral (lost on restart) and dropped once fetched. Polling is
# what lets a long scan finish without tripping a proxy's request timeout.
JOBS: dict[str, dict] = {}
MAX_JOBS = 64
NO_STORE = {"Cache-Control": "no-store"}  # keep proxies from caching poll results


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return INDEX_HTML


@app.get("/catsec.png", include_in_schema=False)
async def logo() -> FileResponse:
    return FileResponse(LOGO_PATH, media_type="image/png")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Async scan jobs
# ---------------------------------------------------------------------------

def _prune_jobs() -> None:
    """Drop the oldest finished jobs so abandoned results don't accumulate."""
    for jid in list(JOBS):
        if len(JOBS) <= MAX_JOBS:
            break
        if JOBS[jid]["status"] in ("done", "error"):
            del JOBS[jid]


async def _scan_url(u: str, depth: int, max_pages: int, render: bool, cloak: bool) -> dict:
    report = await ss.scan_url(u, depth=depth, max_pages=max_pages,
                               render=render, cloak=cloak)
    return ss.report_to_dict(report, "he")


async def _scan_har(parsed: dict, filename: str | None) -> dict:
    # HAR analysis is CPU-bound and synchronous — keep it off the event loop.
    report = await asyncio.to_thread(ss.scan_har_dict, parsed)
    report.start_url = filename or "(HAR capture)"
    return ss.report_to_dict(report, "he")


async def _run_job(job_id: str, coro) -> None:
    try:
        result = await asyncio.wait_for(coro, timeout=SCAN_TIMEOUT)
        JOBS[job_id] = {"status": "done", "result": result}
    except asyncio.TimeoutError:
        JOBS[job_id] = {"status": "error",
                        "error": f"הסריקה חרגה ממגבלת הזמן ({SCAN_TIMEOUT} שניות) ונעצרה. "
                                 f"נסו עומק או מספר עמודים קטן יותר, או בטלו רינדור עם דפדפן."}
    except SystemExit as e:  # headless Chrome unavailable
        JOBS[job_id] = {"status": "error", "error": f"מנוע הדפדפן אינו זמין: {e}"}
    except Exception as e:  # noqa: BLE001
        JOBS[job_id] = {"status": "error",
                        "error": f"שגיאה במהלך הסריקה: {type(e).__name__}: {e}"}


@app.post("/api/scan")
async def scan_start(
    mode: str = Form("url"),
    url: str = Form(""),
    depth: int = Form(1),
    max_pages: int = Form(20),
    render: bool = Form(False),
    cloak: bool = Form(True),
    har: UploadFile | None = File(None),
):
    """Validate input, start the scan as a background job, return its id."""
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
        coro = _scan_har(parsed, har.filename)
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
        coro = _scan_url(u, depth, max_pages, use_render, bool(cloak))

    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"status": "running"}
    _prune_jobs()
    asyncio.create_task(_run_job(job_id, coro))
    return JSONResponse({"job_id": job_id}, headers=NO_STORE)


@app.get("/api/scan/{job_id}")
async def scan_status(job_id: str):
    """Poll a scan job. Returns running, or the final report/error (then forgets it)."""
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "מזהה סריקה לא נמצא (ייתכן שפג תוקפו). נסו שוב.")
    if job["status"] == "running":
        return JSONResponse({"status": "running"}, headers=NO_STORE)
    if job["status"] == "error":
        err = JOBS.pop(job_id, job)["error"]
        return JSONResponse({"status": "error", "detail": err}, headers=NO_STORE)
    result = JOBS.pop(job_id, job)["result"]
    return JSONResponse({"status": "done", "report": result}, headers=NO_STORE)
