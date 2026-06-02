# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# sitesweep — hardened multi-stage build
# Builder installs Python deps into a venv; runtime adds Chromium (for --render),
# runs as a non-root user, and is meant to run with a read-only root FS.
# For a slim static/HAR-only image, delete the Chromium block and set
# SITESWEEP_ALLOW_RENDER=0.
# ---------------------------------------------------------------------------

FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    TMPDIR=/tmp \
    SITESWEEP_ALLOW_RENDER=1

COPY --from=builder /opt/venv /opt/venv

# Chromium + its OS libraries for headless rendering (--render).
# Remove this RUN for a slim image without browser rendering.
RUN mkdir -p /ms-playwright \
 && playwright install --with-deps chromium \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /ms-playwright

WORKDIR /app
COPY --chown=appuser:appuser sitesweep.py app.py ./
COPY --chown=appuser:appuser templates ./templates

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').getcode()==200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
