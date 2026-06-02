#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx[http2]", "selectolax"]
# ///
"""
sitesweep — merchant site violation & SEO-injection checker.

Crawls a site one level deep (configurable), fetches the actually-served HTML,
and scans for content violations (gambling, pharma, adult, counterfeit) and the
mechanics of parasite-SEO / link-injection compromises: hidden/cloaked content,
injected dofollow links to violation domains, foreign-script anomalies,
suspicious JS, violation slugs in URLs, and UA-based cloaking.

Design principle: it judges the content the server actually returns, using
weighted signals with corroboration — not search-index keyword guilt-by-
association. A single weak term (e.g. "slot" on a site called "asiatico")
never trips a verdict on its own.

Usage:
    sitesweep.py https://example.com                      # static crawl, depth 1
    sitesweep.py https://example.com --render             # headless Chrome (runs JS)
    sitesweep.py --har capture.har                        # analyze a saved HAR
    sitesweep.py https://example.com --format md -o report.md
    sitesweep.py https://x.com --html-file saved.html     # single local page

Install (macOS, venv):
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    playwright install chromium        # only if you use --render
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Protocol
from urllib.parse import urljoin, urlparse

# ----------------------------------------------------------------------------
# Detection knowledge base
# ----------------------------------------------------------------------------

# Strong terms are high-confidence: their presence is itself meaningful.
# Weak terms collide with legitimate usage and only count with corroboration.
VIOLATIONS: dict[str, dict[str, list[str]]] = {
    "gambling": {
        "strong": [
            "casino", "casinò", "kasino", "gambling", "sportsbook", "baccarat",
            "roulette", "blackjack", "slot gacor", "situs slot", "judi online",
            "judi bola", "bandar judi", "agen judi", "togel", "maxwin",
            "spielautomaten", "online spielbank", "casino en ligne", "casino online",
            "娱乐城", "老虎机", "百家乐", "赌场", "博彩", "在线赌博",
            "บาคาร่า", "สล็อตออนไลน์", "เว็บพนัน", "카지노", "바카라", "온라인카지노",
            "nhà cái", "cá cược bóng đá",
        ],
        "weak": [
            "slot", "slots", "bet", "betting", "wager", "poker", "jackpot",
            "rtp", "pragmatic", "scatter", "freespins", "free spins", "casinos",
        ],
    },
    "pharma": {
        "strong": [
            "viagra", "cialis", "tadalafil", "sildenafil", "kamagra",
            "buy pills online", "no prescription", "без рецепта",
        ],
        "weak": ["pharmacy", "ed pills", "generic"],
    },
    "adult": {
        "strong": ["xxx porn", "live sex cam", "escort service", "成人视频"],
        "weak": ["adult", "webcam"],
    },
    "counterfeit": {
        "strong": ["replica watches", "fake rolex", "cheap jordans replica", "高仿"],
        "weak": ["replica", "knockoff"],
    },
}

# Inline-style fragments used to push injected content off-screen / invisible.
HIDDEN_STYLE_PATTERNS = [
    re.compile(r"position\s*:\s*absolute[^;}\"']*?(?:left|top)\s*:\s*-\d{3,}px", re.I),
    re.compile(r"(?:left|top|text-indent)\s*:\s*-\d{4,}px", re.I),
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I),
    re.compile(r"font-size\s*:\s*0(?:px)?\b", re.I),
    re.compile(r"(?:width|height)\s*:\s*[01]px", re.I),
    re.compile(r"clip\s*:\s*rect\(0", re.I),
]

# Off-screen rules hiding inside <style> blocks (class-based cloaking).
STYLE_BLOCK_HIDDEN = re.compile(r"(?:left|top|text-indent)\s*:\s*-\d{4,}px", re.I)

SUSPICIOUS_JS = {
    "eval(": re.compile(r"\beval\s*\("),
    "atob(": re.compile(r"\batob\s*\("),
    "unescape(": re.compile(r"\bunescape\s*\("),
    "String.fromCharCode": re.compile(r"fromCharCode"),
    "document.write": re.compile(r"document\s*\.\s*write"),
    "meta-refresh redirect": re.compile(r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+url=", re.I),
    "location redirect": re.compile(r"(?:window\.)?location(?:\.href)?\s*=", re.I),
}

# Domains whose name itself advertises a violation category.
DOMAIN_VIOLATION = re.compile(
    r"(casino|gambl|\bbet\b|betting|\bslot\b|jackpot|poker|togel|judi|baccarat|"
    r"viagra|cialis|pharmacy|replica)",
    re.I,
)

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
GOOGLEBOT_UA = ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

SCRIPT_RANGES = {
    "Hebrew": (0x0590, 0x05FF),
    "CJK": (0x4E00, 0x9FFF),
    "Thai": (0x0E00, 0x0E7F),
    "Cyrillic": (0x0400, 0x04FF),
    "Hangul": (0xAC00, 0xD7AF),
    "Arabic": (0x0600, 0x06FF),
}


# ----------------------------------------------------------------------------
# Technology fingerprinting knowledge base (informational only)
# ----------------------------------------------------------------------------

# Fixed signatures. A tech is detected if ANY html token is present, or any of
# its (header, value-regex) pairs matches. Version, when discoverable, is filled
# separately (generator metas, versioned asset filenames) — see fingerprint_tech.
TECH_SIGNATURES = [
    {"name": "WordPress", "category": "cms",
     "html": ["wp-content", "wp-includes", "/wp-json"]},
    {"name": "Elementor", "category": "page-builder",
     "html": ["data-elementor", "/wp-content/plugins/elementor", "elementor-"],
     "asset": "plugins/elementor"},
    {"name": "WooCommerce", "category": "ecommerce",
     "html": ["woocommerce", "/wp-content/plugins/woocommerce"],
     "asset": "plugins/woocommerce"},
    {"name": "Shopify", "category": "ecommerce",
     "html": ["cdn.shopify.com", "shopify.theme"],
     "headers": [("x-shopify-stage", r".")]},
    {"name": "Wix", "category": "cms",
     "html": ["static.wixstatic.com"],
     "headers": [("x-wix-request-id", r"."), ("server", r"\bPepyaka\b")]},
    {"name": "Joomla", "category": "cms",
     "html": ["/media/jui/", "com_content", "/media/system/js/"]},
    {"name": "Drupal", "category": "cms",
     "html": ["/sites/default/", "drupal.settings", "drupal-settings-json"],
     "headers": [("x-generator", r"Drupal")]},
    {"name": "jQuery", "category": "js-lib", "html": ["jquery"]},
    {"name": "React", "category": "js-lib",
     "html": ["data-reactroot", "react.production.min.js", "react-dom"]},
    {"name": "Vue", "category": "js-lib",
     "html": ["vue.min.js", "vue.runtime", "__vue__"]},
    {"name": "Cloudflare", "category": "cdn", "html": [],
     "headers": [("cf-ray", r"."), ("server", r"cloudflare")]},
]

TECH_CATEGORY_NAMES = {
    "cms": {"en": "CMS", "he": "מערכת ניהול תוכן"},
    "page-builder": {"en": "page builder", "he": "בונה עמודים"},
    "ecommerce": {"en": "e-commerce", "he": "מסחר"},
    "plugin": {"en": "plugin", "he": "תוסף"},
    "theme": {"en": "theme", "he": "תבנית"},
    "server": {"en": "server", "he": "שרת"},
    "cdn": {"en": "CDN", "he": "CDN"},
    "js-lib": {"en": "JS library", "he": "ספריית JS"},
}


def _tech_cat(c: str, lang: str) -> str:
    return TECH_CATEGORY_NAMES.get(c, {}).get(lang, c)


# Names seen in <meta generator> that are the CMS/platform itself, not a plugin.
GENERATOR_CATEGORY = {
    "wordpress": "cms", "joomla": "cms", "drupal": "cms", "wix": "cms",
    "shopify": "ecommerce", "woocommerce": "ecommerce", "elementor": "page-builder",
    "blogger": "cms", "ghost": "cms", "hugo": "cms", "squarespace": "cms",
}

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_VERSION_TAIL_RE = re.compile(r'^(.*?)[\s\-]+v?(\d+(?:\.\d+)+)\s*$')
_WP_PLUGIN_RE = re.compile(r'/wp-content/plugins/([a-z0-9][a-z0-9\-]*)/', re.I)
_WP_THEME_RE = re.compile(r'/wp-content/themes/([a-z0-9][a-z0-9\-]*)/', re.I)
_JQUERY_VER_RE = re.compile(r'jquery[-/.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', re.I)


def _asset_version(low_html: str, marker: str) -> str | None:
    """Pull a version from a versioned asset URL, e.g. .../<marker>/...?ver=3.21.0"""
    m = re.search(re.escape(marker) + r"/[^\"'>\s]*?[?&]ver=(\d+(?:\.\d+)+)", low_html)
    return m.group(1) if m else None


def _slug_title(slug: str) -> str:
    return slug.replace("-", " ").strip().title()


def fingerprint_tech(url: str, html: str, headers: dict[str, str] | None = None) -> list[dict]:
    """Return [{'name','category','version'|None,'evidence'}], deduped by name.

    Pure: runs on HTML already fetched by the crawler/HAR loader (plus response
    headers when available). Informational only — callers must never let this
    influence the verdict or score."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    low = html.lower()
    found: dict[str, dict] = {}

    def add(name: str, category: str, version: str | None = None, evidence: str = "") -> None:
        name = (name or "").strip()
        if not name:
            return
        cur = found.get(name)
        if cur is None:
            found[name] = {"name": name, "category": category,
                           "version": version, "evidence": evidence[:80]}
        elif version and not cur.get("version"):
            cur["version"] = version
            if evidence:
                cur["evidence"] = evidence[:80]

    # 1) fixed signatures (html tokens / response headers)
    for sig in TECH_SIGNATURES:
        hit = next((tok for tok in sig.get("html", []) if tok in low), None)
        ev = hit
        if not hit:
            for hname, pat in sig.get("headers", []):
                hv = headers.get(hname, "")
                if hv and re.search(pat, hv, re.I):
                    hit, ev = True, f"{hname}: {hv}"
                    break
        if hit:
            ver = _asset_version(low, sig["asset"]) if sig.get("asset") else None
            if sig["name"] == "jQuery":
                m = (_JQUERY_VER_RE.search(low)
                     or re.search(r"jquery[^\"'>\s]*?[?&]ver=(\d+(?:\.\d+)+)", low))
                ver = ver or (m.group(1) if m else None)
            add(sig["name"], sig["category"], ver, evidence=str(ev))

    # 2) <meta generator> — names the platform and often a plugin + version
    for content in _GENERATOR_RE.findall(html):
        content = content.strip()
        m = _VERSION_TAIL_RE.match(content)
        gname, gver = (m.group(1).strip(), m.group(2)) if m else (content, None)
        cat = GENERATOR_CATEGORY.get(gname.lower(), "plugin")
        add(gname, cat, gver, evidence=f"generator: {content}")

    # 3) WordPress plugin / theme slugs (Elementor & WooCommerce already named)
    for slug in sorted(set(s.lower() for s in _WP_PLUGIN_RE.findall(html))):
        if slug in ("elementor", "woocommerce"):
            continue
        add(_slug_title(slug), "plugin", _asset_version(low, "plugins/" + slug),
            evidence=f"/wp-content/plugins/{slug}/")
    for slug in sorted(set(s.lower() for s in _WP_THEME_RE.findall(html))):
        add(_slug_title(slug), "theme", _asset_version(low, "themes/" + slug),
            evidence=f"/wp-content/themes/{slug}/")

    # 4) server / X-Powered-By response headers
    srv = headers.get("server", "")
    if srv and "cloudflare" not in srv.lower():
        nm, _, sv = srv.partition("/")
        add(nm.strip() or "server", "server", (sv.split()[0] if sv else None),
            evidence=f"Server: {srv}")
    xpb = headers.get("x-powered-by", "")
    if xpb:
        nm, _, sv = xpb.partition("/")
        add(nm.strip() or xpb, "server", (sv.split()[0] if sv else None),
            evidence=f"X-Powered-By: {xpb}")

    # future: map (name, version) -> known CVEs for a risk hint.
    return list(found.values())


def _aggregate_tech(pages) -> list[dict]:
    """Union of per-page tech, deduped by name, preferring an entry with a version."""
    out: dict[str, dict] = {}
    for p in pages:
        for t in (getattr(p, "tech", None) or []):
            cur = out.get(t["name"])
            if cur is None:
                out[t["name"]] = dict(t)
            elif t.get("version") and not cur.get("version"):
                cur["version"] = t["version"]
                cur["evidence"] = t.get("evidence", cur.get("evidence"))
    return list(out.values())


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    code: str
    severity: str               # info | low | med | high
    params: dict = field(default_factory=dict)


@dataclass
class PageFinding:
    url: str
    status: int = 0
    verdict: str = "CLEAN"          # CLEAN | SUSPICIOUS | INFECTED | ERROR
    score: int = 0
    signals: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    violation_links: list[str] = field(default_factory=list)
    hidden_blocks: int = 0
    hidden_links: int = 0
    keyword_summary: dict[str, dict[str, int]] = field(default_factory=dict)
    tech: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass
class SiteReport:
    start_url: str
    pages: list[PageFinding] = field(default_factory=list)
    ioc_domains: list[str] = field(default_factory=list)
    cloaking: dict | None = None
    request_violations: list[str] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    index_check: dict | None = None
    history_check: dict | None = None
    verdict: str = "CLEAN"

    def worst(self) -> str:
        order = {"CLEAN": 0, "SUSPICIOUS": 1, "INFECTED": 2}
        v = max((p.verdict for p in self.pages if p.verdict != "ERROR"),
                key=lambda x: order.get(x, 0), default="CLEAN")
        if self.cloaking and self.cloaking.get("cloaked"):
            v = "INFECTED"
        if self.request_violations and order.get(v, 0) < 1:
            v = "SUSPICIOUS"
        # Exposure dimension (search index / history) is scored conservatively:
        # it can only bump a CLEAN live site to SUSPICIOUS ("historical/index-lag —
        # confirm manually"), never declare the live site INFECTED on its own.
        if order.get(v, 0) < 1 and (
                (self.index_check or {}).get("indexed_violations") or
                (self.history_check or {}).get("archived_violations")):
            v = "SUSPICIOUS"
        return v


# ----------------------------------------------------------------------------
# i18n — bilingual rendering of findings, verdicts, recommendations
# ----------------------------------------------------------------------------

CATEGORY_NAMES = {
    "gambling": {"en": "gambling", "he": "הימורים"},
    "pharma": {"en": "pharmaceuticals", "he": "תרופות מרשם"},
    "adult": {"en": "adult content", "he": "תוכן מבוגרים"},
    "counterfeit": {"en": "counterfeit goods", "he": "מוצרים מזויפים"},
}


def _cat(c: str, lang: str) -> str:
    return CATEGORY_NAMES.get(c, {}).get(lang, c)


# Each entry: code -> {lang: fn(params) -> str}. 'why' adds a short explanation.
MESSAGES: dict[str, dict[str, callable]] = {
    "VIOLATION_KW": {
        "en": lambda p: f"{p['count']} high-confidence {_cat(p['category'],'en')} terms in page content",
        "he": lambda p: f"נמצאו {p['count']} אזכורים של מונחי {_cat(p['category'],'he')} בתוכן העמוד (זיהוי בביטחון גבוה)",
    },
    "CLOAKED_VIOLATION_BLOCKS": {
        "en": lambda p: f"{p['count']} hidden block(s) concealing violation content",
        "he": lambda p: f"{p['count']} בלוקי תוכן מוסתרים המכילים תוכן מפר — תוכן שמוסתר מהגולש אך נקרא על ידי מנועי החיפוש",
    },
    "HIDDEN_VIOLATION_LINKS": {
        "en": lambda p: f"{p['count']} violation links inside hidden blocks",
        "he": lambda p: f"{p['count']} קישורים לאתרי הפרה המוסתרים בתוך בלוקים נסתרים",
    },
    "DOFOLLOW_VIOLATION_LINKS": {
        "en": lambda p: f"{p['count']} dofollow links to violation domains (pass SEO equity)",
        "he": lambda p: f"{p['count']} קישורי dofollow לדומיינים מפרים — מעבירים \"כוח דירוג\" מהאתר אל אתרי ההפרה",
    },
    "NOFOLLOW_VIOLATION_LINKS": {
        "en": lambda p: f"{p['count']} links to violation domains (nofollow)",
        "he": lambda p: f"{p['count']} קישורים לדומיינים מפרים (מסומנים nofollow)",
    },
    "URL_SLUG": {
        "en": lambda p: f"violation keyword in URL path: '{p['slug']}'",
        "he": lambda p: f"כתובת ה-URL מכילה מילת הפרה בנתיב: '{p['slug']}'",
    },
    "FOREIGN_SCRIPT": {
        "en": lambda p: "foreign-script anomaly: " + ", ".join(f"{k}={v}" for k, v in p['scripts'].items()),
        "he": lambda p: "אנומליית שפה — זוהה תוכן בכתב שאינו תואם לשפת האתר: " + ", ".join(f"{k}={v}" for k, v in p['scripts'].items()),
    },
    "SUSPICIOUS_JS": {
        "en": lambda p: "suspicious JS: " + ", ".join(p['items']),
        "he": lambda p: "קוד JavaScript חשוד (עשוי לשמש להזרקה או הפניה): " + ", ".join(p['items']),
    },
    "STYLE_OFFSCREEN": {
        "en": lambda p: "off-screen positioning rule inside a <style> block",
        "he": lambda p: "כלל מיקום מחוץ למסך בתוך בלוק <style> — טכניקת הסתרה אפשרית",
    },
    "BARE_HIDDEN": {
        "en": lambda p: f"note: {p['count']} hidden element(s) with no concealed violation content — likely legitimate UI",
        "he": lambda p: f"לתשומת לב: {p['count']} אלמנטים מוסתרים ללא תוכן מפר — ככל הנראה רכיבי ממשק לגיטימיים (תפריטים, נגישות)",
    },
    "INDEX_VIOLATION": {
        "en": lambda p: f"{p['count']} page(s) indexed by Google under this domain with "
                        f"{', '.join(_cat(c, 'en') for c in p['categories'])} content — possible historical "
                        f"compromise or index residue; verify against the live site",
        "he": lambda p: f"נמצאו {p['count']} עמודים מאונדקסים בגוגל תחת הדומיין עם תוכן "
                        f"{', '.join(_cat(c, 'he') for c in p['categories'])} — ייתכן פריצה היסטורית או שאריות "
                        f"באינדקס; יש לאמת מול האתר החי.",
    },
    "INDEX_CLEAN": {
        "en": lambda p: "no violation content indexed under the domain",
        "he": lambda p: "לא נמצא תוכן מפר מאונדקס תחת הדומיין.",
    },
    "INDEX_SKIPPED": {
        "en": lambda p: "index check not performed (no search API key configured)",
        "he": lambda p: "בדיקת אינדקס לא בוצעה (לא הוגדר מפתח API לחיפוש).",
    },
    "HISTORY_VIOLATION": {
        "en": lambda p: f"the Wayback archive holds {p['count']} gambling/violation URL(s) under the "
                        f"domain between {p['first_seen']} and {p['last_seen']} — evidence of a historical compromise",
        "he": lambda p: f"הארכיון (Wayback) מכיל {p['count']} כתובות הימורים/הפרה תחת הדומיין בין "
                        f"{p['first_seen']} ל-{p['last_seen']} — עדות לפריצה היסטורית.",
    },
    "HISTORY_CLEAN": {
        "en": lambda p: "no violation URLs found in the historical archive",
        "he": lambda p: "לא נמצאו כתובות מפרות בארכיון ההיסטורי.",
    },
}


def render_finding(finding: "Finding", lang: str = "en") -> str:
    fns = MESSAGES.get(finding.code)
    if not fns:
        return finding.code
    return fns.get(lang, fns["en"])(finding.params)


VERDICT_TEXT = {
    "INFECTED": {
        "en": ("INFECTED", "Injected violation content or active violation links were found."),
        "he": ("נגוע", "באתר נמצא תוכן מפר מוזרק או קישורי הפרה פעילים."),
    },
    "SUSPICIOUS": {
        "en": ("SUSPICIOUS", "Indicators were found that warrant manual review."),
        "he": ("חשוד", "נמצאו אינדיקציות המצריכות בדיקה ידנית לפני הכרעה."),
    },
    "CLEAN": {
        "en": ("CLEAN", "No violation content or SEO-injection signatures were found."),
        "he": ("תקין", "לא נמצאו סממני הפרה או הזרקת SEO בתוכן שנבדק."),
    },
    "ERROR": {
        "en": ("ERROR", "The page could not be fetched."),
        "he": ("שגיאה", "לא ניתן היה לאחזר את העמוד."),
    },
}

RECOMMENDATION = {
    "INFECTED": {
        "he": ("מומלץ לטפל בדחיפות: לאתר ולהסיר את התוכן המוזרק, לזהות ולסגור את דרך הכניסה "
               "(תוסף פגיע, סיסמה שדלפה), להחליף סיסמאות, ולבדוק את מצב האתר ב-Google Search Console."),
        "en": ("Urgent: locate and remove the injected content, find and close the entry vector, "
               "rotate credentials, and check Google Search Console for security/manual actions."),
    },
    "SUSPICIOUS": {
        "he": ("מומלץ לבצע בדיקה ידנית של הממצאים: לוודא האם מדובר בתוכן מפר אמיתי, בשריד היסטורי "
               "של פריצה שטופלה, או בזיהוי שגוי הנובע מהתנגשות מילות מפתח."),
        "en": ("Review the findings manually to confirm whether this is real violation content, "
               "a remediated historical artifact, or a keyword-collision false positive."),
    },
    "CLEAN": {
        "he": "לא נדרשת פעולה. מומלץ לשמור על עדכוני אבטחה שוטפים ועל סריקות תקופתיות.",
        "en": "No action required. Keep security patches current and re-scan periodically.",
    },
}


def he_cloaking(cloaking: dict) -> str:
    if cloaking.get("cloaked"):
        return ("זוהתה הסוואה (Cloaking): מוגש תוכן שונה למנוע החיפוש (Googlebot) לעומת הגולש הרגיל — "
                "סימן מובהק להזרקת SEO זדונית.")
    return "לא זוהתה הסוואה: התוכן שמוגש ל-Googlebot זהה לזה שמוגש לגולש."


# ----------------------------------------------------------------------------
# HTML analysis (pure, testable — no network)
# ----------------------------------------------------------------------------

def _is_latin(term: str) -> bool:
    return all(ord(c) < 0x250 for c in term)


def _compile_matchers() -> dict[str, dict[str, list]]:
    """Pre-compile per-term matchers. Latin terms use word boundaries to avoid
    substring false positives (e.g. 'cialis' inside 'specialist'); non-Latin
    scripts (CJK/Thai) have no word boundaries, so plain substring counting."""
    compiled: dict[str, dict[str, list]] = {}
    for cat, groups in VIOLATIONS.items():
        compiled[cat] = {}
        for strength, terms in groups.items():
            matchers = []
            for t in terms:
                tl = t.lower()
                if _is_latin(tl):
                    matchers.append(re.compile(r"\b" + re.escape(tl) + r"\b", re.UNICODE))
                else:
                    matchers.append(tl)  # substring count for non-Latin
            compiled[cat][strength] = matchers
    return compiled


_MATCHERS = _compile_matchers()


def _count_term(text_lower: str, matcher) -> int:
    if isinstance(matcher, str):
        return text_lower.count(matcher)
    return len(matcher.findall(text_lower))


def scan_keywords(text_lower: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for cat, groups in _MATCHERS.items():
        strong = sum(_count_term(text_lower, m) for m in groups["strong"])
        weak = sum(_count_term(text_lower, m) for m in groups["weak"])
        if strong or weak:
            out[cat] = {"strong": strong, "weak": weak}
    return out


def detect_hidden(tree, raw_html: str) -> tuple[int, list, list]:
    """Return (#hidden containers, all hidden nodes, suspicious hidden nodes).

    A hidden node is only *suspicious* (i.e. cloaking) when it actually conceals
    content a crawler would index — links or a meaningful run of text. Bare
    hidden elements (skip-nav, dropdowns, ARIA, modals) are legitimate and common,
    so they are counted but not treated as a violation signal on their own."""
    hidden_nodes, suspicious = [], []
    for node in tree.css("[style]"):
        style = node.attributes.get("style") or ""
        if any(p.search(style) for p in HIDDEN_STYLE_PATTERNS):
            hidden_nodes.append(node)
            anchors = node.css("a[href]")
            text = (node.text() or "").strip()
            if anchors or len(text) >= 120:
                suspicious.append(node)
    return len(hidden_nodes), hidden_nodes, suspicious


def analyze_links(tree, base_url: str) -> dict:
    base_host = urlparse(base_url).netloc.lower().replace("www.", "")
    internal, external = [], []
    violation_links, dofollow_violation = [], []
    for a in tree.css("a[href]"):
        href = (a.attributes.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absu = urljoin(base_url, href)
        host = urlparse(absu).netloc.lower().replace("www.", "")
        if not host:
            continue
        anchor = (a.text() or "").strip().lower()
        rel = (a.attributes.get("rel") or "").lower()
        is_violation = bool(DOMAIN_VIOLATION.search(host)) or _anchor_is_violation(anchor)
        rec = {"url": absu, "host": host, "rel": rel, "anchor": anchor[:60]}
        if base_host and base_host in host:
            internal.append(rec)
        else:
            external.append(rec)
        if is_violation:
            violation_links.append(rec)
            if "nofollow" not in rel and "sponsored" not in rel:
                dofollow_violation.append(rec)
    return {
        "internal": internal, "external": external,
        "violation": violation_links, "dofollow_violation": dofollow_violation,
    }


def _anchor_is_violation(anchor: str) -> bool:
    for groups in VIOLATIONS.values():
        if any(w in anchor for w in groups["strong"]):
            return True
    return False


def count_links_in_nodes(nodes) -> tuple[int, list]:
    total, recs = 0, []
    for n in nodes:
        for a in n.css("a[href]"):
            total += 1
            href = (a.attributes.get("href") or "").strip()
            host = urlparse(urljoin("http://x/", href)).netloc.lower()
            if DOMAIN_VIOLATION.search(host) or _anchor_is_violation((a.text() or "").lower()):
                recs.append(host or href[:60])
    return total, recs


def script_anomaly(raw_html: str, declared_lang: str | None) -> dict[str, int]:
    counts = {name: 0 for name in SCRIPT_RANGES}
    for ch in raw_html:
        o = ord(ch)
        for name, (lo, hi) in SCRIPT_RANGES.items():
            if lo <= o <= hi:
                counts[name] += 1
                break
    return {k: v for k, v in counts.items() if v > 30}


def detect_suspicious_js(raw_html: str) -> list[str]:
    hits = []
    for label, pat in SUSPICIOUS_JS.items():
        if pat.search(raw_html):
            hits.append(label)
    return hits


def url_path_violation(url: str) -> str | None:
    path = urlparse(url).path.lower()
    m = DOMAIN_VIOLATION.search(path)
    return m.group(0) if m else None


def analyze_page(url: str, html: str, parser_cls, headers: dict | None = None) -> PageFinding:
    f = PageFinding(url=url)
    if not html:
        f.verdict, f.error = "ERROR", "empty body"
        return f
    tree = parser_cls(html)
    low = html.lower()

    declared_lang = None
    html_node = tree.css_first("html")
    if html_node:
        declared_lang = (html_node.attributes.get("lang") or "").lower() or None

    kw = scan_keywords(low)
    f.keyword_summary = kw

    n_hidden, hidden_nodes, suspicious_hidden = detect_hidden(tree, html)
    f.hidden_blocks = n_hidden
    hidden_link_count, hidden_link_hosts = count_links_in_nodes(suspicious_hidden)
    f.hidden_links = hidden_link_count
    # hidden blocks that conceal violation content specifically
    cloaked_violation = 0
    for node in suspicious_hidden:
        ntext = (node.text() or "").lower()
        if any(m if isinstance(m, str) and m in ntext else
               (not isinstance(m, str) and m.search(ntext))
               for grp in _MATCHERS.values() for m in grp["strong"]):
            cloaked_violation += 1
        elif node.css("a[href]") and hidden_link_hosts:
            cloaked_violation += 1

    links = analyze_links(tree, url)
    for rec in links["violation"]:
        f.violation_links.append(rec["url"])

    scripts = script_anomaly(html, declared_lang)
    js = detect_suspicious_js(html)
    path_hit = url_path_violation(url)

    # ---- scoring (corroboration-based; bare hidden elements never trip alone) ----
    score = 0
    findings: list[Finding] = []

    def add(code: str, sev: str, **params) -> None:
        findings.append(Finding(code=code, severity=sev, params=params))

    for cat, c in kw.items():
        if c["strong"] >= 1:
            score += min(c["strong"], 30) * 3
            add("VIOLATION_KW", "high", category=cat, count=c["strong"])
    if cloaked_violation:
        score += 25 + min(cloaked_violation, 60)
        add("CLOAKED_VIOLATION_BLOCKS", "high", count=cloaked_violation)
    if hidden_link_count and hidden_link_hosts:
        score += 25 + min(len(hidden_link_hosts), 50)
        add("HIDDEN_VIOLATION_LINKS", "high", count=len(hidden_link_hosts))
    if links["dofollow_violation"]:
        score += 25 + min(len(links["dofollow_violation"]), 50)
        add("DOFOLLOW_VIOLATION_LINKS", "high", count=len(links["dofollow_violation"]))
    elif links["violation"]:
        score += 10
        add("NOFOLLOW_VIOLATION_LINKS", "med", count=len(links["violation"]))
    if path_hit:
        score += 12
        add("URL_SLUG", "med", slug=path_hit)
    if scripts and any(k.get("strong") for k in kw.values()):
        clash = [s for s in scripts if not _script_matches_lang(s, declared_lang)]
        if clash:
            score += 15
            add("FOREIGN_SCRIPT", "med", scripts={s: scripts[s] for s in clash})
    # supporting evidence only — scored when something else already fired
    if score > 0:
        if js:
            score += 4 * len(js)
            add("SUSPICIOUS_JS", "low", items=list(js))
        if STYLE_BLOCK_HIDDEN.search(html):
            score += 8
            add("STYLE_OFFSCREEN", "low")
    if n_hidden and not (cloaked_violation or (hidden_link_count and hidden_link_hosts)):
        add("BARE_HIDDEN", "info", count=n_hidden)

    f.score = score
    f.findings = findings
    f.signals = [render_finding(x, "en") for x in findings]
    if score >= 40:
        f.verdict = "INFECTED"
    elif score >= 15:
        f.verdict = "SUSPICIOUS"
    else:
        f.verdict = "CLEAN"
    # Informational only — fingerprinting must not influence score/verdict above.
    f.tech = fingerprint_tech(url, html, headers)
    return f


def _script_matches_lang(script: str, lang: str | None) -> bool:
    if not lang:
        return False
    table = {"Hebrew": "he", "CJK": ("zh", "ja"), "Hangul": "ko",
             "Thai": "th", "Cyrillic": ("ru", "uk", "bg"), "Arabic": "ar"}
    want = table.get(script)
    if want is None:
        return False
    want = (want,) if isinstance(want, str) else want
    return any(lang.startswith(w) for w in want)


# ----------------------------------------------------------------------------
# Crawler (async)
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Fetchers (pluggable: static httpx, or headless Chrome via Playwright)
# ----------------------------------------------------------------------------

class HttpxFetcher:
    """Static fetch — fast, sees server-rendered HTML only (no JS execution)."""

    def __init__(self):
        self.client = None

    async def __aenter__(self):
        import httpx
        self.client = httpx.AsyncClient(http2=True, verify=True)
        return self

    async def __aexit__(self, *exc):
        if self.client:
            await self.client.aclose()

    async def fetch(self, url: str, ua: str) -> tuple[int, str, str, dict]:
        try:
            r = await self.client.get(url, headers={"User-Agent": ua},
                                      timeout=15.0, follow_redirects=True)
            ctype = r.headers.get("content-type", "")
            body = r.text if "html" in ctype or not ctype else ""
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status_code, body, str(r.url), hdrs
        except Exception as e:  # noqa: BLE001
            return 0, "", f"ERROR:{type(e).__name__}:{e}", {}


class ChromeFetcher:
    """Headless Chrome via Playwright — executes JS, so it catches
    client-side / DOM-injected content that static fetching would miss.

    Requires: pip install playwright && playwright install chromium"""

    def __init__(self, wait_ms: int = 1500, nav_timeout: int = 25000):
        self.wait_ms = wait_ms
        self.nav_timeout = nav_timeout
        self._pw = None
        self.browser = None

    async def __aenter__(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise SystemExit(
                "headless Chrome mode needs Playwright:\n"
                "    pip install playwright && playwright install chromium"
            ) from e
        self._pw = await async_playwright().start()
        try:
            self.browser = await self._pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        except Exception as e:  # noqa: BLE001 - typically missing browser binary
            await self._pw.stop()
            raise SystemExit(
                f"could not launch headless Chromium ({e}).\n"
                "install the browser once with:  playwright install chromium"
            ) from e
        return self

    async def __aexit__(self, *exc):
        if self.browser:
            await self.browser.close()
        if self._pw:
            await self._pw.stop()

    async def fetch(self, url: str, ua: str) -> tuple[int, str, str, dict]:
        ctx = await self.browser.new_context(user_agent=ua, ignore_https_errors=True)
        try:
            page = await ctx.new_page()
            resp = await page.goto(url, wait_until="domcontentloaded",
                                   timeout=self.nav_timeout)
            await page.wait_for_timeout(self.wait_ms)  # let injection JS run
            html = await page.content()
            status = resp.status if resp else 0
            hdrs = {k.lower(): v for k, v in (resp.headers if resp else {}).items()}
            return status, html, page.url, hdrs
        except Exception as e:  # noqa: BLE001
            return 0, "", f"ERROR:{type(e).__name__}:{e}", {}
        finally:
            await ctx.close()


# ----------------------------------------------------------------------------
# Crawler (async, fetcher-agnostic)
# ----------------------------------------------------------------------------

def extract_internal_links(html: str, base_url: str, parser_cls) -> list[str]:
    tree = parser_cls(html)
    base_host = urlparse(base_url).netloc.lower().replace("www.", "")
    seen, out = set(), []
    for a in tree.css("a[href]"):
        href = (a.attributes.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absu = urljoin(base_url, href).split("#")[0]
        host = urlparse(absu).netloc.lower().replace("www.", "")
        if base_host and base_host in host and absu not in seen:
            seen.add(absu)
            out.append(absu)
    return out


async def crawl(fetcher, start_url: str, depth: int, max_pages: int,
                concurrency: int, ua: str, parser_cls) -> list[tuple[str, int, str, dict]]:
    results: list[tuple[str, int, str, dict]] = []
    visited: set[str] = set()
    sem = asyncio.Semaphore(concurrency)

    async def grab(u: str) -> tuple[str, int, str, dict]:
        async with sem:
            st, body, _final, hdrs = await fetcher.fetch(u, ua)
        return (u, st, body, hdrs)

    frontier = [start_url]
    for level in range(depth + 1):
        batch = [u for u in frontier if u not in visited][:max_pages - len(visited)]
        if not batch:
            break
        for u in batch:
            visited.add(u)
        fetched = await asyncio.gather(*(grab(u) for u in batch))
        results.extend(fetched)
        if level < depth:
            nxt: list[str] = []
            for (_u, st, body, _h) in fetched:
                if body and 200 <= st < 300:
                    nxt.extend(extract_internal_links(body, _u, parser_cls))
            frontier = nxt
        if len(visited) >= max_pages:
            break
    return results


async def cloak_check(fetcher, start_url: str, parser_cls) -> dict:
    s1, b1, _u1, _h1 = await fetcher.fetch(start_url, DEFAULT_UA)
    s2, b2, _u2, _h2 = await fetcher.fetch(start_url, GOOGLEBOT_UA)
    f_user = analyze_page(start_url, b1, parser_cls)
    f_bot = analyze_page(start_url, b2, parser_cls)
    user_g = sum(v.get("strong", 0) for v in f_user.keyword_summary.values())
    bot_g = sum(v.get("strong", 0) for v in f_bot.keyword_summary.values())
    cloaked = (bot_g - user_g) >= 5 or (f_bot.score - f_user.score) >= 30
    return {"cloaked": cloaked, "user_score": f_user.score, "bot_score": f_bot.score,
            "user_strong_kw": user_g, "bot_strong_kw": bot_g}


# ----------------------------------------------------------------------------
# HAR input mode
# ----------------------------------------------------------------------------

def load_har_data(data: dict, parser_cls) -> tuple[list[PageFinding], list[str]]:
    """Analyze a parsed HAR object (dict). Returns (page findings, violation
    request hosts). Used by both the CLI and the web upload path."""
    import base64
    entries = data.get("log", {}).get("entries", [])
    findings: list[PageFinding] = []
    violation_requests: set[str] = set()
    seen: set[str] = set()
    for e in entries:
        url = e.get("request", {}).get("url", "")
        host = urlparse(url).netloc.lower()
        if host and DOMAIN_VIOLATION.search(host):
            violation_requests.add(host)
        resp = e.get("response", {})
        content = resp.get("content", {}) or {}
        if "text/html" not in (content.get("mimeType", "") or ""):
            continue
        text = content.get("text", "") or ""
        if content.get("encoding") == "base64":
            try:
                text = base64.b64decode(text).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
        if not text or url in seen:
            continue
        seen.add(url)
        hdrs = {(h.get("name") or "").lower(): h.get("value") or ""
                for h in (resp.get("headers") or [])}
        pf = analyze_page(url, text, parser_cls, headers=hdrs)
        pf.status = resp.get("status", 0)
        findings.append(pf)
    return findings, sorted(violation_requests)


def load_har(path: str, parser_cls) -> tuple[list[PageFinding], list[str]]:
    """Analyze a saved .har file. Requires a HAR saved *with response content*."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    return load_har_data(data, parser_cls)


# ----------------------------------------------------------------------------
# Search-index & historical exposure (site-level)
#
# Detects whether the *domain itself* is indexed / was archived with violation
# content — the signal a live crawl can miss (index lag, cloaked-then-removed).
# Correctness rule: only count results whose host == the target domain (or a
# subdomain). A page that merely mentions a brand or shares a keyword is never a
# signal — that is the index-collision false positive this whole tool avoids.
# ----------------------------------------------------------------------------

# A few Hebrew gambling terms to widen the index query for .il sites.
INDEX_HE_TERMS = ["הימור", "קזינו", "סלוט"]


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str


class SearchProvider(Protocol):
    async def site_search(self, domain: str, query: str) -> list[SearchHit]: ...


class NullProvider:
    """Used when no API keys are present. Never raises; yields nothing."""
    errored = False

    async def site_search(self, domain: str, query: str) -> list[SearchHit]:
        return []


class GoogleCSEProvider:
    """Google Custom Search JSON API. The CSE must be set to search the entire web.
    On quota/4xx/network error it returns [] and sets `errored` (never raises)."""

    def __init__(self, api_key: str, cse_id: str):
        self.api_key = api_key
        self.cse_id = cse_id
        self.errored = False

    async def site_search(self, domain: str, query: str) -> list[SearchHit]:
        import httpx
        params = {"key": self.api_key, "cx": self.cse_id,
                  "q": f"site:{domain} {query}", "num": 10}
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get("https://www.googleapis.com/customsearch/v1",
                                params=params, timeout=15.0)
            if r.status_code >= 400:
                self.errored = True
                return []
            items = r.json().get("items", []) or []
        except Exception:  # noqa: BLE001
            self.errored = True
            return []
        return [SearchHit(title=it.get("title", ""), url=it.get("link", ""),
                          snippet=it.get("snippet", "")) for it in items]


class SerpApiProvider:
    """Optional SerpAPI backend. Same contract as GoogleCSEProvider."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.errored = False

    async def site_search(self, domain: str, query: str) -> list[SearchHit]:
        import httpx
        params = {"api_key": self.api_key, "engine": "google",
                  "q": f"site:{domain} {query}", "num": 10}
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get("https://serpapi.com/search.json",
                                params=params, timeout=15.0)
            if r.status_code >= 400:
                self.errored = True
                return []
            items = r.json().get("organic_results", []) or []
        except Exception:  # noqa: BLE001
            self.errored = True
            return []
        return [SearchHit(title=it.get("title", ""), url=it.get("link", ""),
                          snippet=it.get("snippet", "")) for it in items]


def get_search_provider() -> SearchProvider:
    """Pick a provider from the environment: Google first, then SerpAPI, else Null."""
    if os.environ.get("GOOGLE_API_KEY") and os.environ.get("GOOGLE_CSE_ID"):
        return GoogleCSEProvider(os.environ["GOOGLE_API_KEY"], os.environ["GOOGLE_CSE_ID"])
    if os.environ.get("SERPAPI_KEY"):
        return SerpApiProvider(os.environ["SERPAPI_KEY"])
    return NullProvider()


def has_search_provider() -> bool:
    return not isinstance(get_search_provider(), NullProvider)


def _host_on_domain(url: str, domain: str) -> bool:
    """True only if url's host == domain or is a subdomain of it (the FP guard)."""
    host = urlparse(url).netloc.lower().replace("www.", "")
    d = domain.lower().replace("www.", "")
    return bool(host) and (host == d or host.endswith("." + d))


async def index_check(domain: str, provider: SearchProvider,
                      categories: list[str] | None = None) -> dict:
    """Query the search index for violation content *hosted on* `domain`."""
    if isinstance(provider, NullProvider):
        return {"status": "skipped_no_provider", "indexed_violations": [], "queries_run": 0}
    cats = categories or list(VIOLATIONS)
    indexed: list[dict] = []
    queries = 0
    for cat in cats:
        terms = VIOLATIONS[cat]["strong"][:8]
        if cat == "gambling":
            terms = terms[:6] + INDEX_HE_TERMS
        query = " OR ".join(f'"{t}"' for t in terms)
        queries += 1
        for hit in await provider.site_search(domain, query):
            if _host_on_domain(hit.url, domain):
                indexed.append({"category": cat, "url": hit.url, "title": hit.title})
    status = "provider_error" if getattr(provider, "errored", False) else "ok"
    return {"status": status, "indexed_violations": indexed, "queries_run": queries}


_CDX_FILTER = "casino|slot|bet|gambl|judi|togel|baccarat|viagra|cialis"


async def history_check(domain: str) -> dict:
    """Query the Wayback Machine CDX API for archived violation URLs on the domain."""
    import httpx
    d = domain.lower().replace("www.", "")
    url = ("http://web.archive.org/cdx/search/cdx"
           f"?url={d}/*&output=json&collapse=urlkey&fl=timestamp,original"
           f"&filter=original:.*({_CDX_FILTER}).*&limit=10000")
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(url, timeout=15.0)
        rows = r.json()
    except Exception:  # noqa: BLE001
        return {"status": "unavailable", "archived_violations": [],
                "first_seen": None, "last_seen": None, "count": 0}
    archived: list[dict] = []
    for row in (rows[1:] if isinstance(rows, list) else []):  # row 0 is the header
        if len(row) < 2:
            continue
        ts, original = row[0], row[1]
        if _host_on_domain(original, d):
            archived.append({"url": original, "timestamp": ts})
    times = sorted(o["timestamp"] for o in archived if o["timestamp"])
    return {"status": "ok", "archived_violations": archived,
            "first_seen": times[0][:8] if times else None,
            "last_seen": times[-1][:8] if times else None, "count": len(archived)}


def site_findings(report: "SiteReport") -> list[Finding]:
    """Site-level findings derived from the exposure checks, rendered at report level."""
    out: list[Finding] = []
    ic = report.index_check
    if ic:
        if ic.get("status") == "skipped_no_provider":
            out.append(Finding("INDEX_SKIPPED", "info"))
        elif ic.get("indexed_violations"):
            cats = sorted({v["category"] for v in ic["indexed_violations"]})
            out.append(Finding("INDEX_VIOLATION", "high",
                               {"count": len(ic["indexed_violations"]), "categories": cats}))
        elif ic.get("status") == "ok":
            out.append(Finding("INDEX_CLEAN", "info"))
    hc = report.history_check
    if hc and hc.get("status") == "ok":
        if hc.get("archived_violations"):
            out.append(Finding("HISTORY_VIOLATION", "med",
                               {"count": hc.get("count", len(hc["archived_violations"])),
                                "first_seen": hc.get("first_seen"),
                                "last_seen": hc.get("last_seen")}))
        else:
            out.append(Finding("HISTORY_CLEAN", "info"))
    return out


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------

C = {"INFECTED": "\033[1;31m", "SUSPICIOUS": "\033[1;33m",
     "CLEAN": "\033[1;32m", "ERROR": "\033[1;90m", "R": "\033[0m", "B": "\033[1m"}


def build_iocs(report: SiteReport) -> list[str]:
    hosts = set()
    for p in report.pages:
        for u in p.violation_links:
            h = urlparse(u).netloc.lower()
            if h:
                hosts.add(h)
    return sorted(hosts)


def render_text(report: SiteReport, color: bool = True, lang: str = "en") -> str:
    def c(tag): return C[tag] if color else ""
    R = c("R")
    out = []
    v = report.verdict
    vlabel = VERDICT_TEXT.get(v, VERDICT_TEXT["CLEAN"])[lang][0] if lang != "en" else v
    out.append(f"\n{c('B')}== sitesweep report =={R}")
    out.append(f"target   : {report.start_url}")
    out.append(f"pages    : {len(report.pages)}")
    out.append(f"verdict  : {c(v)}{vlabel}{R}")
    if report.cloaking:
        cl = report.cloaking
        flag = f"{c('INFECTED')}CLOAKING DETECTED{R}" if cl["cloaked"] else "no cloaking"
        out.append(f"cloaking : {flag} "
                   f"(user kw={cl['user_strong_kw']} / googlebot kw={cl['bot_strong_kw']})")
    out.append("")
    for p in sorted(report.pages, key=lambda x: -x.score):
        if p.verdict == "ERROR":
            out.append(f"  {c('ERROR')}[ERROR]{R} {p.url}  ({p.error})")
            continue
        if p.verdict == "CLEAN" and not p.findings:
            continue
        plabel = VERDICT_TEXT[p.verdict][lang][0] if lang != "en" else p.verdict
        out.append(f"  {c(p.verdict)}[{plabel}]{R} score={p.score}  {p.url}")
        for fnd in p.findings:
            out.append(f"        - {render_finding(fnd, lang)}")
        for vl in p.violation_links[:8]:
            out.append(f"        -> {vl}")
    clean = sum(1 for p in report.pages if p.verdict == "CLEAN")
    if clean == len([p for p in report.pages if p.verdict != "ERROR"]):
        out.append(f"  {c('CLEAN')}All scanned pages clean.{R}")
    iocs = build_iocs(report)
    if report.request_violations:
        out.append(f"\n{c('SUSPICIOUS')}Violation domains in captured requests "
                   f"({len(report.request_violations)}):{R}")
        for h in report.request_violations:
            out.append(f"  {h}")
    if iocs:
        out.append(f"\n{c('B')}IoC domains ({len(iocs)}):{R}")
        for h in iocs:
            out.append(f"  {h}")
    if report.technologies:
        title = "טכנולוגיות שזוהו" if lang == "he" else "Technologies"
        out.append(f"\n{c('B')}{title}:{R}")
        for t in report.technologies:
            ver = f" {t['version']}" if t.get("version") else ""
            out.append(f"  {t['name']}{ver}  [{_tech_cat(t.get('category', ''), lang)}]")
    sfs = site_findings(report)
    if sfs:
        title = "חשיפה באינדקס/היסטוריה" if lang == "he" else "Index / history exposure"
        out.append(f"\n{c('B')}{title}:{R}")
        for fnd in sfs:
            out.append(f"  - {render_finding(fnd, lang)}")
        for v in (report.index_check or {}).get("indexed_violations", [])[:8]:
            out.append(f"      -> {v['url']}")
        for v in (report.history_check or {}).get("archived_violations", [])[:8]:
            out.append(f"      -> {v.get('timestamp', '')[:8]} {v['url']}")
    out.append("")
    return "\n".join(out)


def render_md(report: SiteReport) -> str:
    iocs = build_iocs(report)
    out = [f"# sitesweep report — {report.start_url}", "",
           f"**Verdict:** {report.verdict}  ",
           f"**Pages scanned:** {len(report.pages)}  "]
    if report.cloaking:
        cl = report.cloaking
        out.append(f"**Cloaking:** {'DETECTED' if cl['cloaked'] else 'none'} "
                   f"(user kw={cl['user_strong_kw']}, googlebot kw={cl['bot_strong_kw']})  ")
    out += ["", "## Findings", ""]
    flagged = [p for p in report.pages if p.signals or p.verdict in ("INFECTED", "SUSPICIOUS")]
    if not flagged:
        out.append("_All scanned pages clean._")
    for p in sorted(flagged, key=lambda x: -x.score):
        out.append(f"### `{p.url}` — {p.verdict} (score {p.score})")
        for s in p.signals:
            out.append(f"- {s}")
        for vl in p.violation_links[:12]:
            out.append(f"  - `{vl}`")
        out.append("")
    if report.request_violations:
        out += ["## Violation domains in captured requests", ""]
        out += [f"- `{h}`" for h in report.request_violations]
        out.append("")
    if iocs:
        out += ["## IoC domains", ""] + [f"- `{h}`" for h in iocs]
    if report.technologies:
        out += ["", "## Technologies", ""]
        for t in report.technologies:
            ver = f" {t['version']}" if t.get("version") else ""
            out.append(f"- **{t['name']}**{ver} — {t.get('category', '')}")
    sfs = site_findings(report)
    if sfs:
        out += ["", "## Index / history exposure", ""]
        out += [f"- {render_finding(f, 'en')}" for f in sfs]
        for v in (report.index_check or {}).get("indexed_violations", [])[:12]:
            out.append(f"  - `{v['url']}`")
        for v in (report.history_check or {}).get("archived_violations", [])[:12]:
            out.append(f"  - `{v.get('timestamp', '')[:8]}` `{v['url']}`")
    return "\n".join(out)


def render_json(report: SiteReport) -> str:
    d = asdict(report)
    d["ioc_domains"] = build_iocs(report)
    return json.dumps(d, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------
# High-level API (used by the CLI and the web app)
# ----------------------------------------------------------------------------

def get_parser():
    try:
        from selectolax.lexbor import LexborHTMLParser as P
    except Exception:  # noqa: BLE001
        from selectolax.parser import HTMLParser as P
    return P


async def scan_url(url: str, depth: int = 1, max_pages: int = 25, concurrency: int = 6,
                   render: bool = False, cloak: bool = True, render_wait: int = 1500,
                   ua: str = DEFAULT_UA, index_check: bool = False,
                   history_check: bool = False) -> SiteReport:
    Parser = get_parser()
    report = SiteReport(start_url=url)
    domain = urlparse(url).netloc.replace("www.", "")
    fetcher = ChromeFetcher(render_wait) if render else HttpxFetcher()
    # Exposure checks hit external services and are independent of the crawl, so
    # run them concurrently. globals() sidesteps the param/function name clash.
    aux_names, aux_coros = [], []
    if index_check:
        aux_names.append("index_check")
        aux_coros.append(globals()["index_check"](domain, get_search_provider()))
    if history_check:
        aux_names.append("history_check")
        aux_coros.append(globals()["history_check"](domain))
    aux_task = asyncio.gather(*aux_coros) if aux_coros else None
    async with fetcher:
        fetched = await crawl(fetcher, url, depth, max_pages, concurrency, ua, Parser)
        if cloak:
            report.cloaking = await cloak_check(fetcher, url, Parser)
    if aux_task is not None:
        for name, res in zip(aux_names, await aux_task):
            setattr(report, name, res)
    for (u, st, body, hdrs) in fetched:
        if st == 0:
            report.pages.append(PageFinding(url=u, status=0, verdict="ERROR", error=body))
        else:
            pf = analyze_page(u, body, Parser, headers=hdrs)
            pf.status = st
            report.pages.append(pf)
    report.technologies = _aggregate_tech(report.pages)
    report.verdict = report.worst()
    report.ioc_domains = build_iocs(report)
    return report


def scan_har_dict(data: dict, domain: str | None = None,
                  index_check: bool = False, history_check: bool = False) -> SiteReport:
    Parser = get_parser()
    report = SiteReport(start_url="(HAR capture)")
    pages, req = load_har_data(data, Parser)
    report.pages = pages
    report.request_violations = req
    report.technologies = _aggregate_tech(pages)
    if domain is None and pages:
        domain = urlparse(pages[0].url).netloc.replace("www.", "")
    if domain and (index_check or history_check):
        async def _aux() -> dict:
            res: dict = {}
            if index_check:
                res["index_check"] = await globals()["index_check"](domain, get_search_provider())
            if history_check:
                res["history_check"] = await globals()["history_check"](domain)
            return res
        for k, v in asyncio.run(_aux()).items():
            setattr(report, k, v)
    report.verdict = report.worst()
    report.ioc_domains = build_iocs(report)
    return report


def report_to_dict(report: SiteReport, lang: str = "he") -> dict:
    """Localized, JSON-friendly structure for the web frontend or API consumers."""
    def page_dict(p: PageFinding) -> dict:
        label, _ = VERDICT_TEXT.get(p.verdict, VERDICT_TEXT["CLEAN"])[lang]
        return {
            "url": p.url, "status": p.status, "verdict": p.verdict,
            "verdict_label": label, "score": p.score,
            "findings": [{"severity": f.severity, "code": f.code,
                          "text": render_finding(f, lang)} for f in p.findings],
            "violation_links": p.violation_links,
            "keyword_summary": p.keyword_summary,
            "error": p.error,
        }

    label, desc = VERDICT_TEXT.get(report.verdict, VERDICT_TEXT["CLEAN"])[lang]
    out: dict = {
        "target": report.start_url,
        "verdict": report.verdict,
        "verdict_label": label,
        "verdict_desc": desc,
        "recommendation": RECOMMENDATION[report.verdict][lang],
        "page_count": len(report.pages),
        "pages": [page_dict(p) for p in sorted(report.pages, key=lambda x: -x.score)],
        "ioc_domains": build_iocs(report),
        "request_violations": report.request_violations,
    }
    if report.cloaking:
        out["cloaking"] = {
            **report.cloaking,
            "text": he_cloaking(report.cloaking) if lang == "he" else (
                "cloaking detected" if report.cloaking["cloaked"] else "no cloaking"),
        }

    out["technologies"] = [
        {**t, "category_label": _tech_cat(t.get("category", ""), lang)}
        for t in report.technologies
    ]

    sf = site_findings(report)
    if report.index_check is not None:
        ic = report.index_check
        text = next((render_finding(f, lang) for f in sf
                     if f.code in ("INDEX_VIOLATION", "INDEX_CLEAN", "INDEX_SKIPPED")), "")
        if ic.get("status") == "provider_error" and not text:
            text = ("בדיקת האינדקס נכשלה (חריגת מכסה או שגיאת שירות)." if lang == "he"
                    else "index check failed (quota or service error)")
        out["index_check"] = {
            "status": ic.get("status"),
            "indexed_violations": ic.get("indexed_violations", []),
            "text": text,
        }
    if report.history_check is not None:
        hc = report.history_check
        text = next((render_finding(f, lang) for f in sf
                     if f.code in ("HISTORY_VIOLATION", "HISTORY_CLEAN")), "")
        if hc.get("status") == "unavailable" and not text:
            text = ("בדיקת ההיסטוריה אינה זמינה כעת." if lang == "he"
                    else "history check unavailable")
        out["history_check"] = {
            "status": hc.get("status"),
            "count": hc.get("count", 0),
            "first_seen": hc.get("first_seen"),
            "last_seen": hc.get("last_seen"),
            "archived_violations": hc.get("archived_violations", []),
            "text": text,
        }
    return out


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Site violation & SEO-injection sweep.")
    ap.add_argument("url", nargs="?", help="start URL (e.g. https://example.com)")
    ap.add_argument("--depth", type=int, default=1, help="link depth to crawl (default 1)")
    ap.add_argument("--max-pages", type=int, default=25, help="max pages to fetch")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--no-cloak-check", action="store_true", help="skip Googlebot cloaking test")
    ap.add_argument("--format", choices=["text", "md", "json"], default="text")
    ap.add_argument("-o", "--output", help="write report to file")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--render", action="store_true",
                    help="fetch with headless Chrome (executes JS; needs Playwright)")
    ap.add_argument("--render-wait", type=int, default=1500,
                    help="ms to wait after load for JS injection (with --render)")
    ap.add_argument("--har", help="analyze a saved .har capture instead of crawling")
    ap.add_argument("--html-file", help="offline: analyze a single local HTML file")
    ap.add_argument("--lang", choices=["en", "he"], default="en", help="report language")
    ap.add_argument("--index-check", action="store_true",
                    help="query the search index for violation content on the domain "
                         "(needs GOOGLE_API_KEY+GOOGLE_CSE_ID or SERPAPI_KEY)")
    ap.add_argument("--history-check", action="store_true",
                    help="query the Wayback archive for historical violation URLs (no key)")
    args = ap.parse_args()

    # ---- HAR mode ----
    if args.har:
        with open(args.har, encoding="utf-8", errors="replace") as fh:
            report = scan_har_dict(json.load(fh), index_check=args.index_check,
                                   history_check=args.history_check)
        report.start_url = args.har

    # ---- single local file ----
    elif args.html_file:
        if not args.url:
            print("--html-file requires a positional URL for link resolution", file=sys.stderr)
            return 2
        Parser = get_parser()
        html = open(args.html_file, encoding="utf-8", errors="replace").read()
        report = SiteReport(start_url=args.url)
        report.pages.append(analyze_page(args.url, html, Parser))
        report.technologies = _aggregate_tech(report.pages)
        report.verdict = report.worst()
        report.ioc_domains = build_iocs(report)

    # ---- live crawl (static or headless Chrome) ----
    else:
        if not args.url:
            ap.print_help()
            return 2
        report = asyncio.run(scan_url(
            args.url, depth=args.depth, max_pages=args.max_pages,
            concurrency=args.concurrency, render=args.render,
            cloak=not args.no_cloak_check, render_wait=args.render_wait,
            ua=args.user_agent, index_check=args.index_check,
            history_check=args.history_check))

    if args.format == "json":
        text = render_json(report)
    elif args.format == "md":
        text = render_md(report)
    else:
        text = render_text(report, color=not args.output, lang=args.lang)

    if args.output:
        open(args.output, "w", encoding="utf-8").write(text)
        print(f"report written to {args.output}  (verdict: {report.verdict})")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
