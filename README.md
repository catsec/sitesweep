# sitesweep

A merchant **site violation & SEO-injection checker** with a Hebrew web front end.
Scans a live site (1 level deep) or a saved **HAR** capture and reports — in Hebrew —
whether the page carries violation content (gambling / pharma / adult / counterfeit)
or the mechanics of a parasite-SEO compromise: hidden/cloaked content, injected
dofollow links to violation domains, foreign-script anomalies, suspicious JS,
violation slugs in URLs, and UA-based cloaking.

**Design principle:** it judges the content actually served, with weighted signals and
corroboration — so a lone weak keyword (e.g. "slot" on a site called *asiatico*) never
trips a verdict. This avoids the index-collision false positives that naive
"domain + keyword" detection produces.

---

## Run with Docker (recommended)

```bash
cp .env.example .env          # then paste your Cloudflare tunnel token into .env
docker compose up -d          # pulls ghcr.io/catsec/sitesweep:latest (amd64/arm64)
```

The image is published by GitHub Actions to **`ghcr.io/catsec/sitesweep`** as a
multi-arch manifest, so the same tag runs on Intel/AMD64 and arm64 (Apple Silicon,
Graviton, Pi 64-bit). To build locally instead of pulling, uncomment `build: .` in
`docker-compose.yml` and run `docker compose build`.

Two services come up:

- **sitesweep** — the app. It publishes **no host port**; nothing is exposed on the LAN.
- **cloudflared** — the Cloudflare Tunnel. Authentication is handled by **Cloudflare Access**
  in front of the tunnel. In the Zero Trust dashboard, point the tunnel's public hostname
  (e.g. `sitesweep.catsec.com`) at the origin **`http://sitesweep:8000`** — that's the app's
  service name on the internal Docker network.

The tunnel token lives in `.env` (`CF_TUNNEL_TOKEN`) and is passed to cloudflared as
`TUNNEL_TOKEN`, so it never appears in the compose file or in the container's process
arguments. `.env` is gitignored; never commit it.

The compose file is hardened: non-root, `cap_drop: ALL`, `no-new-privileges`,
read-only root FS with `tmpfs`, resource limits, health check, log rotation, pinned tags.

The image bundles **Chromium** so the "רינדור עם דפדפן" (headless Chrome) option works.
For a slim static/HAR-only image, delete the Chromium `RUN` block in the `Dockerfile`
and set `SITESWEEP_ALLOW_RENDER=0`.

### Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `SITESWEEP_ALLOW_RENDER` | `1` | allow headless-Chrome rendering |
| `SITESWEEP_MAX_PAGES` | `50` | hard cap on pages per URL scan |
| `SITESWEEP_MAX_HAR_MB` | `40` | max uploaded HAR size |

---

## Run locally (macOS, venv)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium      # only if you'll use rendering

# web UI
uvicorn app:app --host 127.0.0.1 --port 8000

# or the CLI
python sitesweep.py https://example.co.il --lang he
python sitesweep.py --har capture.har --lang he
python sitesweep.py https://example.co.il --render --format md -o report.md
```

---

## CLI reference

```
sitesweep.py [URL] [options]
  --har FILE         analyze a saved HAR instead of crawling
  --html-file FILE   analyze one local HTML file (URL positional for link resolution)
  --render           fetch with headless Chrome (executes JS)
  --render-wait MS   settle time after load for injection JS (default 1500)
  --depth N          crawl depth (default 1)
  --max-pages N      page cap (default 25)
  --no-cloak-check   skip the Googlebot cloaking diff
  --format text|md|json
  --lang en|he
  -o FILE            write report to file
```

---

## How the verdict works

Signals are scored and summed; `>=40` → INFECTED (נגוע), `>=15` → SUSPICIOUS (חשוד),
else CLEAN (תקין). Bare hidden elements, lone weak keywords, and ordinary analytics JS
never reach a verdict on their own — they only count alongside real corroboration.
UA cloaking (different content to Googlebot) or violation domains in network requests
escalate on their own.

## Limitations

- Static fetch won't see JS-only injection — use `--render` / the browser toggle.
- Class-based CSS cloaking is detected heuristically (via `<style>` scan), not full CSS resolution.
- The URL scanner fetches arbitrary hosts by design; if exposing the UI beyond yourself,
  put it behind auth and consider egress restrictions (SSRF).

## Files

```
sitesweep.py        engine + CLI
app.py              FastAPI web app
templates/index.html  Hebrew RTL UI
requirements.txt
Dockerfile          hardened, multi-stage, Chromium included
docker-compose.yml  hardened runtime
```
