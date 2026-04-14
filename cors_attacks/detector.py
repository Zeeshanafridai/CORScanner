"""
CORS Misconfiguration Detector
--------------------------------
Tests all major CORS bypass techniques against a target URL.

Techniques:
  1. Reflected Origin        — server echoes back any Origin
  2. Null Origin             — Origin: null accepted
  3. Prefix Match Bypass     — target.com.attacker.com
  4. Suffix Match Bypass     — attackertarget.com
  5. Subdomain Wildcard      — sub.target.com (subdomain takeover vector)
  6. Protocol Downgrade      — http:// instead of https://
  7. Wildcard with Creds     — Access-Control-Allow-Origin: * with credentials
  8. Trusted Subdomain       — test/dev/staging subdomains
  9. Special Characters      — Origin: https://target.com%60.attacker.com
 10. Vary Header Missing     — caching attack surface
"""

import urllib.parse
from .utils import (
    cors_request, parse_acao, parse_acac, parse_acam,
    R, G, Y, B, M, C, W, DIM, BOLD, RST, severity_label
)


def build_origin_variants(target_url: str, attacker_domain: str = "evil.com") -> list:
    """
    Generate all origin bypass variants for a given target URL.
    Returns list of (name, origin, description) tuples.
    """
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    # Strip www
    base = host.lstrip("www.")

    variants = []

    # 1. Reflected origin test
    variants.append(("reflected",       f"https://{attacker_domain}",
                     "Arbitrary origin — server reflects any value"))

    # 2. Null origin
    variants.append(("null_origin",     "null",
                     "Null origin — sandbox iframes, data: URIs"))

    # 3. Prefix match bypass — attacker domain starts with target
    variants.append(("prefix_match",    f"https://{base}.{attacker_domain}",
                     f"Prefix bypass: {base}.{attacker_domain}"))

    # 4. Suffix match bypass — attacker domain ends with target
    variants.append(("suffix_match",    f"https://attacker{base}",
                     f"Suffix bypass: attacker{base}"))

    # 5. Subdomain variants (wildcard *.target.com)
    variants.append(("subdomain_wild",  f"https://sub.{base}",
                     "Subdomain wildcard — any subdomain accepted"))
    variants.append(("subdomain_xss",   f"https://xss.{base}",
                     "XSS on any subdomain escalates to CORS exploit"))

    # 6. Protocol downgrade
    variants.append(("http_downgrade",  f"http://{host}",
                     "HTTP downgrade — scheme mismatch accepted"))

    # 7. Trusted dev/staging subdomains
    for sub in ("dev", "staging", "test", "qa", "uat", "demo", "beta", "preview"):
        variants.append((f"trusted_sub_{sub}", f"https://{sub}.{base}",
                         f"Trusted subdomain: {sub}.{base}"))

    # 8. Special character injection
    variants.append(("special_backtick",  f"https://{base}%60.{attacker_domain}",
                     "Backtick special char bypass"))
    variants.append(("special_underscore", f"https://{base}_.{attacker_domain}",
                     "Underscore bypass"))

    # 9. Port variations
    for port in ("80", "443", "8080", "8443", "3000", "4000"):
        variants.append((f"port_{port}", f"https://{host}:{port}",
                         f"Non-standard port: {port}"))

    # 10. Exact match with case variation
    variants.append(("uppercase", f"https://{host.upper()}",
                     "Uppercase host — case-insensitive match"))

    return variants


def test_cors(url: str, origin: str, cookies: str = None,
              extra_headers: dict = None, with_preflight: bool = True) -> dict:
    """
    Test a single origin against the target URL.
    Returns result dict with vulnerability assessment.
    """
    result = cors_request(
        url, origin, cookies=cookies,
        extra_headers=extra_headers,
        preflight=with_preflight
    )

    resp = result.get("response", {})
    if not resp:
        return {"vulnerable": False, "error": "No response"}

    resp_headers = resp.get("headers", {})
    acao = parse_acao(resp_headers)
    acac = parse_acac(resp_headers)
    acam = parse_acam(resp_headers)
    vary = resp_headers.get("vary", "")
    status = resp.get("status", 0)

    # Assess vulnerability
    vulnerable = False
    vuln_type = None
    notes = []

    if acao == origin or acao == "*":
        if acao == origin and origin != "null":
            vulnerable = True
            vuln_type = "reflected"
            notes.append(f"Origin reflected: {acao}")
        elif acao == "*" and acac:
            vulnerable = True
            vuln_type = "wildcard_with_creds"
            notes.append("Wildcard + credentials — technically invalid but some browsers accept")
        elif acao == "*":
            vuln_type = "wildcard"
            notes.append("Wildcard ACAO (no credentials — limited impact)")

    if origin == "null" and acao == "null":
        vulnerable = True
        vuln_type = "null_origin"
        notes.append("Null origin accepted — exploitable via sandboxed iframe")

    if not "origin" in vary.lower() and acao:
        notes.append("Vary: Origin missing — potential cache poisoning")

    return {
        "url": url,
        "origin_sent": origin,
        "status": status,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "vary": vary,
        "vulnerable": vulnerable,
        "vuln_type": vuln_type,
        "notes": notes,
        "response_snippet": resp.get("body", "")[:200],
        "preflight": result.get("preflight"),
        "raw_headers": resp_headers,
    }


def scan(url: str, attacker_domain: str = "evil.com", cookies: str = None,
         extra_headers: dict = None, custom_origins: list = None,
         verbose: bool = True, delay: float = 0.0) -> list:
    """
    Full CORS misconfiguration scan against a URL.

    Args:
        url: Target URL
        attacker_domain: Attacker-controlled domain for bypass tests
        cookies: Session cookie string
        extra_headers: Additional request headers
        custom_origins: Extra origins to test
        verbose: Print findings
        delay: Delay between requests (seconds)

    Returns:
        List of vulnerability findings
    """
    import time

    variants = build_origin_variants(url, attacker_domain)

    if custom_origins:
        for o in custom_origins:
            variants.append(("custom", o, "Custom origin"))

    findings = []
    total = len(variants)

    if verbose:
        print(f"\n{C}[*] Scanning {url}{RST}")
        print(f"{DIM}    Testing {total} origin variants...{RST}\n")

    for i, (name, origin, desc) in enumerate(variants):
        if verbose:
            print(f"  {DIM}[{i+1:02d}/{total}]{RST} {origin[:60]:<60}", end="\r", flush=True)

        result = test_cors(url, origin, cookies=cookies,
                           extra_headers=extra_headers, with_preflight=True)
        result["variant_name"] = name
        result["variant_desc"] = desc

        if result.get("vulnerable"):
            findings.append(result)
            if verbose:
                sev = severity_label(result["vuln_type"], result["acac"])
                print(f"\n  {G}[VULN]{RST} {sev} — {name}")
                print(f"         Origin  : {origin}")
                print(f"         ACAO    : {result['acao']}")
                print(f"         ACAC    : {result['acac']}")
                print(f"         Type    : {result['vuln_type']}")
                for note in result["notes"]:
                    print(f"         Note    : {note}")
                print()
        elif result.get("acao") and result["acao"] != "":
            # ACAO present but not vulnerable — informational
            if verbose and name in ("reflected", "null_origin"):
                print(f"\n  {DIM}[INFO]{RST} {name}: ACAO={result['acao']} ACAC={result['acac']}")

        if delay:
            time.sleep(delay)

    if verbose:
        print(f"\r{' '*80}\r", end="")  # clear progress line
        if findings:
            print(f"\n{R}{BOLD}[!] {len(findings)} CORS misconfiguration(s) found{RST}\n")
        else:
            print(f"\n{DIM}[-] No exploitable CORS misconfigurations found{RST}\n")

    return findings
