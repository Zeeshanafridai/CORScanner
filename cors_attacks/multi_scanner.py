"""
Multi-URL Scanner
------------------
Scan multiple endpoints at once.
Supports reading from a file, automatic endpoint discovery
from a base URL, and parallelized scanning.
"""

import urllib.parse
import urllib.request
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from .detector import scan as scan_single
from .utils import R, G, Y, C, DIM, BOLD, RST, SSL_CTX

# Common API/sensitive endpoints to probe
COMMON_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile", "/api/account",
    "/api/users", "/api/v1/user", "/api/v1/me", "/api/v2/user",
    "/user/info", "/user/profile", "/account/info", "/account/profile",
    "/auth/user", "/auth/profile", "/auth/me",
    "/admin/api", "/admin/users",
    "/graphql",
    "/api/settings", "/api/config",
    "/api/keys", "/api/tokens",
    "/.well-known/jwks.json",
    "/api/payments", "/api/billing",
    "/api/orders", "/api/transactions",
]


def discover_endpoints(base_url: str, extra_paths: list = None,
                       verbose: bool = False) -> list:
    """
    Build list of URLs to test from a base URL.
    """
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    urls = [base_url]  # always test the provided URL

    for path in COMMON_ENDPOINTS:
        urls.append(f"{base}{path}")

    if extra_paths:
        for path in extra_paths:
            urls.append(f"{base}{path.lstrip('/')}")

    if verbose:
        print(f"  [*] Probing {len(urls)} endpoints")

    return list(dict.fromkeys(urls))  # deduplicate, preserve order


def scan_multiple(urls: list, attacker_domain: str = "evil.com",
                  cookies: str = None, extra_headers: dict = None,
                  threads: int = 5, verbose: bool = True,
                  delay: float = 0.0) -> dict:
    """
    Scan multiple URLs concurrently.
    Returns dict: url → findings list
    """
    all_findings = {}
    total = len(urls)

    if verbose:
        print(f"\n{C}[*] Multi-URL CORS Scan — {total} endpoints, {threads} threads{RST}\n")

    def scan_url(url):
        try:
            findings = scan_single(
                url,
                attacker_domain=attacker_domain,
                cookies=cookies,
                extra_headers=extra_headers,
                verbose=False,
                delay=delay
            )
            return url, findings
        except Exception as e:
            return url, []

    completed = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_url, url): url for url in urls}
        for future in as_completed(futures):
            url, findings = future.result()
            all_findings[url] = findings
            completed += 1

            if verbose:
                status = (f"{G}[VULN x{len(findings)}]{RST}" if findings
                          else f"{DIM}[ ok ]{RST}")
                print(f"  {status} {url[:70]}")

    vuln_count = sum(len(f) for f in all_findings.values())
    vuln_urls = [u for u, f in all_findings.items() if f]

    if verbose:
        print(f"\n{'-'*60}")
        print(f"  Scanned    : {total} URLs")
        print(f"  Vulnerable : {len(vuln_urls)} URLs ({vuln_count} findings)")
        if vuln_urls:
            print(f"\n  {R}{BOLD}Vulnerable endpoints:{RST}")
            for u in vuln_urls:
                print(f"    {G}→{RST} {u}")
        print()

    return all_findings


def scan_from_file(filepath: str, **kwargs) -> dict:
    """Load URLs from file (one per line) and scan all."""
    with open(filepath) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    print(f"  [*] Loaded {len(urls)} URLs from {filepath}")
    return scan_multiple(urls, **kwargs)
