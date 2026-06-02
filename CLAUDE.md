# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

sitesweep is a merchant **site violation & SEO-injection checker** with a Hebrew RTL web front end. It scans a live site (crawl, default depth 1) or a saved **HAR** capture and reports — in Hebrew or English — whether a page carries violation content (gambling / pharma / adult / counterfeit) or shows the mechanics of a parasite-SEO compromise: hidden/cloaked content, injected dofollow links to violation domains, foreign-script anomalies, suspicious JS, violation slugs in URLs, and UA-based cloaking.

**Core design principle (do not regress this):** the engine judges the content actually served, using *weighted signals with corroboration*, never "domain + keyword" guilt-by-association. A lone weak keyword (e.g. "slot" on a site called *asiatico*) must never trip a verdict on its own. Bare hidden elements, lone weak keywords, and ordinary analytics JS only count alongside real corroboration. When editing the scorer, preserve this — it's what avoids the index-collision false positives that motivated the project.

## Commands

```bash
# Local dev (macOS, venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # only needed for --render / browser toggle

uvicorn app:app --host 127.0.0.1 --port 8000   # web UI on :8000

# CLI (engine is also a self-contained PEP 723 script)
python sitesweep.py https://example.co.il --lang he
python sitesweep.py --har capture.har --lang he
python sitesweep.py https://example.co.il --render --format md -o report.md
python sitesweep.py https://x.com --html-file saved.html   # single local page

# Docker
cp .env.example .env                 # paste Cloudflare tunnel token
docker compose build && docker compose up -d
```

There is **no test suite, linter config, or CI** in this repo. The HTML-analysis layer in `sitesweep.py` (`analyze_page`, `scan_keywords`, `detect_hidden`, `analyze_links`, etc.) is pure and network-free, so it's the natural place to drive with a saved HTML string if you add tests.

## Architecture

Three files do the work; everything else is packaging.

- **`sitesweep.py`** — the entire engine plus a standalone CLI. Layered top-to-bottom:
  1. **Detection knowledge base** (`VIOLATIONS`, `HIDDEN_STYLE_PATTERNS`, `SUSPICIOUS_JS`, `DOMAIN_VIOLATION`, `SCRIPT_RANGES`). `VIOLATIONS` splits every category into `strong` (high-confidence, meaningful alone) and `weak` (collides with legit usage, only counts with corroboration) term lists — including non-Latin scripts.
  2. **HTML analysis (pure, no network):** `analyze_page()` is the heart. It returns a `PageFinding` and is where the **scoring** lives. Latin terms match on word boundaries (avoids "cialis" in "specialist"); non-Latin terms are substring-counted (no word boundaries in CJK/Thai). Thresholds: **score ≥ 40 → INFECTED, ≥ 15 → SUSPICIOUS, else CLEAN.**
  3. **Fetchers (pluggable):** `HttpxFetcher` (static, fast, server HTML only) and `ChromeFetcher` (Playwright headless Chrome, runs JS — catches DOM-injected content static fetch misses). Both expose the same `async fetch(url, ua) -> (status, body, final_url, headers)`.
  4. **Crawler:** `crawl()` is fetcher-agnostic, BFS by level up to `depth`, internal links only, bounded by `max_pages` and a concurrency semaphore. `cloak_check()` fetches the start URL as a normal browser **and** as Googlebot and flags cloaking when the bot sees substantially more violation signal.
  5. **HAR mode:** `load_har_data()` analyzes response bodies from a HAR *saved with response content*, and separately flags violation **request** hosts.
  6. **Reporting / i18n:** findings are emitted as language-neutral `Finding` codes; `MESSAGES`/`VERDICT_TEXT`/`RECOMMENDATION` render them bilingually (en/he). Renderers: `render_text`, `render_md`, `render_json`, and `report_to_dict` (localized JSON for the web/API).
  7. **Tech fingerprinting (informational):** `fingerprint_tech(url, html, headers)` is a pure, data-driven detector (`TECH_SIGNATURES` + generator-meta / WP-slug / asset-version regexes) stored on `PageFinding.tech` and unioned into `SiteReport.technologies`. **It must never affect score/verdict** — `analyze_page` sets `f.tech` *after* the verdict is decided; keep it that way.
  8. **Exposure dimension (site-level, network):** `index_check(domain, provider)` (pluggable `SearchProvider`: `SerpApiProvider`/`NullProvider`, chosen by `get_search_provider()` from `SERPAPI_KEY`; on quota/auth/network failure the provider sets `errored`/`error_reason`, surfaced to the user via `index_error_text()`) and `history_check(domain)` (Wayback CDX, no key). **Both apply the host guard `_host_on_domain` — a result counts only if its host *is* the target domain/subdomain**, never mere keyword/brand co-occurrence (this is the index-collision FP guard, same philosophy as the keyword scorer). Scored conservatively in `SiteReport.worst()`: exposure can bump CLEAN→SUSPICIOUS only, never declare the live site INFECTED alone. Site-level findings come from `site_findings()`.
  - **High-level API** consumed by both entry points: `scan_url()`, `scan_har_dict()`, `report_to_dict()` — both scan functions take `index_check`/`history_check` bools (note: same names as the module-level functions, so they call them via `globals()` to dodge the shadow).

- **`app.py`** — thin FastAPI wrapper. Serves the Hebrew SPA at `/` and a `/health` probe. **Scanning is asynchronous** to survive the ~100s request timeout of a proxy in front of the app (Cloudflare returns an HTML 524 on a slow origin, which the old single-request design tripped): `POST /api/scan` validates input, starts the scan as an `asyncio` task tracked in the in-memory `JOBS` dict, and returns `{job_id}` immediately; the browser polls `GET /api/scan/{id}` (`running` → `done`+report → forgotten, or `error`). `SITESWEEP_SCAN_TIMEOUT` caps a job's wall-clock. The in-memory store assumes a **single uvicorn worker** (the default `CMD`) — adding workers would break job lookup. It clamps untrusted input (depth ≤ 2, `max_pages` ≤ `SITESWEEP_MAX_PAGES`, HAR size ≤ `SITESWEEP_MAX_HAR_MB`) and gates rendering behind `SITESWEEP_ALLOW_RENDER`. Docs endpoints are disabled. All engine logic stays in `sitesweep.py` — keep `app.py` a transport layer.

- **`templates/index.html`** — single-file Hebrew RTL UI (inline CSS/JS), read once at startup into `INDEX_HTML`.

### Adding detections

Most detection work is data, not code: extend the `strong`/`weak` lists in `VIOLATIONS`, or the regex tables. If a new signal needs a score, wire it into `analyze_page` **and** add a corresponding `Finding` code with both `en` and `he` text in `MESSAGES` — the renderers and the web frontend key off the code, so a missing language entry falls back to English/the raw code. Respect the corroboration rule: supporting-only signals (suspicious JS, `STYLE_OFFSCREEN`) are scored *only when something else already fired* (`if score > 0:`).

## Deployment notes

The container publishes **no host port**; a `cloudflared` Cloudflare Tunnel reaches the app at `http://sitesweep:8000` on the internal Docker network, with auth handled by Cloudflare Access in front of the tunnel. The tunnel token lives in `.env` as `CF_TUNNEL_TOKEN` (passed as `TUNNEL_TOKEN`, kept out of process args); `.env` is gitignored — never commit it. The runtime is hardened (non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root FS + tmpfs, resource limits). The image bundles Chromium so the render toggle works; for a slim HAR/static-only image, delete the Chromium `RUN` block in the Dockerfile and set `SITESWEEP_ALLOW_RENDER=0`.

**SSRF note:** the URL scanner fetches arbitrary hosts by design. Anything exposing this UID beyond a single trusted operator must keep it behind auth (as the Cloudflare Access setup does) and consider egress restrictions.
