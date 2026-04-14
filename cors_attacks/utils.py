"""
Core HTTP utilities for CORS testing.
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import time
import socket
from typing import Optional


# Bypass SSL verification for testing
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html, */*",
}

# ANSI colors
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM = "\033[90m"  # dim
BOLD = "\033[1m"
RST = "\033[0m"


def http_request(url: str, method: str = "GET", headers: dict = None,
                 body: bytes = None, timeout: int = 10,
                 follow_redirects: bool = True) -> Optional[dict]:
    """
    Make an HTTP request. Returns dict with status, headers, body.
    """
    req_headers = dict(DEFAULT_HEADERS)
    if headers:
        req_headers.update(headers)

    try:
        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                urllib.request.HTTPRedirectHandler()
            )
        else:
            # No redirect following
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                NoRedirect()
            )

        with opener.open(req, timeout=timeout) as resp:
            resp_headers = dict(resp.headers)
            body_bytes = resp.read(1024 * 512)  # max 512KB
            return {
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp_headers.items()},
                "body": body_bytes.decode("utf-8", errors="replace"),
                "url": resp.url,
                "error": None
            }

    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if e.headers else {}
        try:
            body_bytes = e.read(1024 * 64)
        except Exception:
            body_bytes = b""
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in resp_headers.items()},
            "body": body_bytes.decode("utf-8", errors="replace"),
            "url": url,
            "error": str(e)
        }
    except urllib.error.URLError as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}
    except socket.timeout:
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": "Timeout"}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


def cors_request(url: str, origin: str, method: str = "GET",
                 cookies: str = None, extra_headers: dict = None,
                 preflight: bool = False, request_method: str = "GET",
                 request_headers: str = "Authorization") -> dict:
    """
    Send a CORS request with a spoofed Origin header.
    Optionally send preflight OPTIONS first.
    """
    headers = {"Origin": origin}
    if cookies:
        headers["Cookie"] = cookies
    if extra_headers:
        headers.update(extra_headers)

    results = {}

    if preflight:
        pf_headers = dict(headers)
        pf_headers["Access-Control-Request-Method"] = request_method
        pf_headers["Access-Control-Request-Headers"] = request_headers
        pf_resp = http_request(url, method="OPTIONS", headers=pf_headers)
        results["preflight"] = pf_resp

    main_resp = http_request(url, method=method, headers=headers)
    results["response"] = main_resp
    results["origin_sent"] = origin

    return results


def parse_acao(headers: dict) -> str:
    """Extract Access-Control-Allow-Origin value."""
    return headers.get("access-control-allow-origin", "")


def parse_acac(headers: dict) -> bool:
    """Check if Access-Control-Allow-Credentials is true."""
    val = headers.get("access-control-allow-credentials", "").lower()
    return val == "true"


def parse_acam(headers: dict) -> str:
    """Extract Access-Control-Allow-Methods."""
    return headers.get("access-control-allow-methods", "")


def parse_acah(headers: dict) -> str:
    """Extract Access-Control-Allow-Headers."""
    return headers.get("access-control-allow-headers", "")


def severity_label(vuln_type: str, credentials: bool) -> str:
    """Return colored severity string."""
    if credentials:
        return f"{R}{BOLD}CRITICAL{RST}"
    high_types = ["reflected", "null_origin", "prefix_match", "suffix_match"]
    if vuln_type in high_types:
        return f"{R}HIGH{RST}"
    return f"{Y}MEDIUM{RST}"
