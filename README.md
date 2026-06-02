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
| `SITESWEEP_SCAN_TIMEOUT` | `300` | hard wall-clock cap (seconds) on a single scan job |
| `SERPAPI_KEY` | — | enable the search-index check via SerpAPI (see below) |

---

## Install the container, per platform

The runtime is the same everywhere — two containers (`sitesweep` + `cloudflared`)
defined in `docker-compose.yml`, pulling the multi-arch image from GHCR. Only the
way you install Docker and start the project differs.

**Common to every platform**

1. Get the project files (you need `docker-compose.yml` and `.env.example`):
   ```bash
   git clone https://github.com/catsec/sitesweep.git
   cd sitesweep
   cp .env.example .env        # paste your Cloudflare tunnel token into CF_TUNNEL_TOKEN
   ```
2. If the GHCR package is **private**, authenticate once before pulling
   (create a GitHub token with the `read:packages` scope):
   ```bash
   echo "$GHCR_TOKEN" | docker login ghcr.io -u <your-github-user> --password-stdin
   ```
   If the package has been made public, you can skip this.
3. No host port is published by default — the app is reached through the
   Cloudflare Tunnel hostname you configure in the Zero Trust dashboard
   (origin `http://sitesweep:8000`). For **local testing without the tunnel**,
   uncomment the `ports:` block in `docker-compose.yml` to expose
   `127.0.0.1:8000` and open <http://127.0.0.1:8000>.

### Linux

```bash
# Install Docker Engine + the Compose plugin (Debian/Ubuntu shown)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"     # log out/in so you can run docker without sudo

# from the cloned repo:
docker compose up -d
docker compose logs -f              # watch startup; Ctrl-C to stop watching
```

### macOS

```bash
# Install Docker Desktop (includes Compose v2)
brew install --cask docker          # then launch Docker.app once to start the engine
# (Apple Silicon pulls the arm64 image automatically; Intel Macs pull amd64)

# from the cloned repo:
docker compose up -d
```

### Windows

Install **Docker Desktop for Windows** (WSL 2 backend recommended), then from a
PowerShell prompt in the cloned repo:

```powershell
docker compose up -d
docker compose logs -f
```

If you don't have `git`, download the repo Zip from GitHub (**Code → Download ZIP**),
extract it, and run the same commands inside the extracted folder. Edit `.env`
in any text editor (e.g. Notepad) and paste the tunnel token.

### Synology NAS (DSM 7)

Use **Container Manager** (Package Center → install *Container Manager*; on
DSM 7.0–7.1 it's called *Docker*). Works on **64-bit** models — x86_64 (Intel/AMD,
pulls `amd64`) and arm64 (aarch64, pulls `arm64`). 32-bit ARM models are not
supported.

1. Copy the project folder to the NAS (e.g. `/volume1/docker/sitesweep`) via
   File Station or an SMB share — include `docker-compose.yml` and your
   filled-in `.env`.
2. In **Container Manager → Project → Create**:
   - **Path:** the folder you copied.
   - **Source:** *Use existing docker-compose.yml*.
   - Container Manager reads `.env` from that folder for `CF_TUNNEL_TOKEN`.
3. Build/Run the project. Container Manager pulls the image and starts both
   services; the tunnel connects outbound, so **no router port-forwarding is
   needed** and you should not map a NAS port to the app.
4. If the GHCR package is private, add a registry login under
   **Container Manager → Registry → Settings** (registry `ghcr.io`, your GitHub
   user, a `read:packages` token) before creating the project.

> Note: the image bundles Chromium for the "render with browser" option, which is
> RAM-hungry. On NAS units with ≤2 GB RAM, set `SITESWEEP_ALLOW_RENDER=0` in the
> compose `environment:` block (HAR + static scans still work) or raise the
> memory limit to suit your model.
>
> The compose file caps CPU with `cpu_shares` (a relative weight) rather than a hard
> `cpus:` limit on purpose — Synology's kernel lacks CFS CPU-quota support, so a hard
> limit fails with *"NanoCPUs can not be set."*

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
  --index-check      query the search index for violation content on the domain
  --history-check    query the Wayback archive for historical violation URLs
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

## Search-index & history exposure

Two optional **site-level** checks catch what a live crawl alone can miss — a page
that was indexed or archived with violation content even though the live HTML now
looks clean (index lag, or a hack that was cleaned but still lingers in the search
index / the Wayback Machine):

- **Search-index check** (`--index-check`, UI checkbox) — searches the index for
  violation content **hosted on the domain itself**. The critical guard: a result
  only counts if its host equals the target domain (or a subdomain). A site merely
  *mentioning* a brand, or sharing a keyword, is never counted — so a restaurant
  named *asiatico* is not flagged because gambling pages about "slot a tema asiatico"
  exist elsewhere. Needs a search provider (below); without one it self-skips.
- **Wayback history check** (`--history-check`, UI checkbox) — queries the Internet
  Archive CDX API (free, no key) for archived violation URLs on the domain, with the
  same host guard, and reports the first/last seen dates.

**Verdict impact is deliberately conservative:** if the live pages are CLEAN but the
index/history shows violations on the domain, the verdict becomes **SUSPICIOUS**, not
INFECTED — i.e. "historical or index-lag, confirm manually." These checks never
declare the live site infected on their own; they only corroborate a live finding.

### Setting up the index check (SerpAPI)

The index check searches for violation content **hosted on the target domain**
(`site:<domain> …`) via **SerpAPI**, which runs the query through an official
search API:

1. Sign up at <https://serpapi.com/> and copy your API key.
2. Put it in `.env` (Docker reads it via `docker-compose.yml`) or export it for the CLI:
   ```
   SERPAPI_KEY=your-serpapi-key
   ```
3. The UI checkbox enables itself once the server sees the key (via `/api/capabilities`).

SerpAPI's free tier is 250 searches/month; sitesweep sends ~1 query per violation
category, so a scan costs a handful. If the quota is exhausted (or any other provider
error occurs) the scan still completes and the report says so. Without a key the index
check simply self-skips —
the Wayback history check still runs keyless.

## Technology fingerprinting

Every scan also reports the **stack behind the site** — CMS / page builder / e-commerce
(WordPress, Elementor, WooCommerce, Shopify, Wix, Joomla, Drupal…), notable WP
plugins/themes and their versions where exposed, JS libraries, server and CDN (from
response headers). This is **informational only** and never affects the score or verdict;
it's there to speed up remediation and risk profiling.

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
